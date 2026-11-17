import { execFileSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { isSensitiveFilePath } from "./context-enricher.js";

export interface GitWorkspaceContext {
  isGitRepo: boolean;
  branch: string;
  statusShort: string;
  changedFiles: string[];
  diff: string;
  stagedDiff: string;
  rawDiff?: string;
  recentCommits?: string[];
  branchCommitsSinceBase?: string[];
}

function safeGit(args: string[], cwd: string, maxBuffer = 4 * 1024 * 1024): string {
  try {
    return execFileSync("git", args, {
      cwd,
      encoding: "utf8",
      maxBuffer,
      stdio: ["ignore", "pipe", "ignore"]
    }).trim();
  } catch {
    return "";
  }
}

/**
 * Splits a multi-file git diff by `diff --git` sections and distributes `maxDiffChars`
 * fairly across all changed files (giving small files their full diff and redistributing
 * unused budget to larger files) so files at the end of the alphabet are never dropped.
 */
export function budgetMultiFileDiff(
  rawDiff: string,
  statSummary: string,
  maxDiffChars = 45000
): string {
  if (!rawDiff) return "";
  const header = statSummary ? `=== GIT DIFF STAT ===\n${statSummary}\n\n=== FILE DIFFS ===\n` : "";
  const availableBudget = Math.max(2000, maxDiffChars - header.length);

  if (rawDiff.length <= availableBudget) {
    return `${header}${rawDiff}`;
  }

  const chunks = rawDiff
    .split(/(?=^diff --git )/m)
    .map((c) => c.trim())
    .filter(Boolean);

  if (chunks.length <= 1) {
    return `${header}${rawDiff.slice(0, availableBudget)}\n...[TRUNCATED]`;
  }

  // Two-pass fair allocation: small files take only what they need; remaining budget is shared by large files
  const allocations = new Array<number>(chunks.length).fill(0);
  let remainingBudget = availableBudget;
  const unresolvedIndices = chunks.map((_, idx) => idx);

  while (unresolvedIndices.length > 0) {
    const share = Math.max(400, Math.floor(remainingBudget / unresolvedIndices.length));
    let anyFitCompletely = false;

    for (let i = unresolvedIndices.length - 1; i >= 0; i--) {
      const idx = unresolvedIndices[i];
      if (chunks[idx].length <= share) {
        allocations[idx] = chunks[idx].length;
        remainingBudget -= chunks[idx].length;
        unresolvedIndices.splice(i, 1);
        anyFitCompletely = true;
      }
    }

    if (!anyFitCompletely) {
      for (const idx of unresolvedIndices) {
        allocations[idx] = share;
      }
      break;
    }
  }

  const budgetedChunks = chunks.map((chunk, idx) => {
    const limit = allocations[idx];
    if (chunk.length <= limit) return chunk;
    return `${chunk.slice(0, limit)}\n...[FILE DIFF TRUNCATED]`;
  });

  return `${header}${budgetedChunks.join("\n\n")}`;
}

export function collectGitContext(cwd: string = process.cwd(), maxDiffChars = 45000): GitWorkspaceContext {
  const insideWorkTree = safeGit(["rev-parse", "--is-inside-work-tree"], cwd);
  if (insideWorkTree !== "true") {
    return {
      isGitRepo: false,
      branch: "",
      statusShort: "",
      changedFiles: [],
      diff: "",
      stagedDiff: ""
    };
  }

  const branch = safeGit(["rev-parse", "--abbrev-ref", "HEAD"], cwd) || "HEAD";

  // Tracked modified/staged files + non-ignored untracked source/doc files
  const trackedDiffNames = safeGit(["diff", "HEAD", "--name-only"], cwd);
  const untrackedRaw = safeGit(["ls-files", "--others", "--exclude-standard"], cwd);
  const statusShort = safeGit(["status", "--short"], cwd);

  let rawDiff = safeGit(["diff", "HEAD", "-U6", "--ignore-space-at-eol"], cwd);
  let statSummary = safeGit(["diff", "HEAD", "--stat"], cwd);

  if (!rawDiff) {
    rawDiff = safeGit(["diff", "-U6", "--ignore-space-at-eol"], cwd);
    statSummary = safeGit(["diff", "--stat"], cwd);
  }

  let changedFiles = trackedDiffNames
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean);

  // Synthesize standard `diff --git` sections for newly created untracked text files
  // so `jev_verify_diff` and `jev_audit_code` see new files even before `git add`.
  const untrackedFiles = untrackedRaw
    .split(/\r?\n/)
    .map((l) => l.trim())
    .filter(Boolean)
    .filter(
      (rel) =>
        !isSensitiveFilePath(rel) &&
        !/\.(png|jpg|jpeg|gif|webp|ico|pdf|zip|tar|gz|tgz|woff2?|ttf|eot|exe|dll|so|dylib|db|sqlite3?)$/i.test(
          rel
        )
    )
    .slice(0, 25);

  const untrackedChunks: string[] = [];
  const untrackedStatLines: string[] = [];
  for (const rel of untrackedFiles) {
    const absPath = path.join(cwd, rel);
    try {
      if (!fs.existsSync(absPath)) continue;
      const stat = fs.statSync(absPath);
      if (!stat.isFile() || stat.size > 128 * 1024) continue;
      const content = fs.readFileSync(absPath, "utf8");
      if (content.includes("\u0000")) continue;
      const lines = content.split(/\r?\n/);
      const plusBody = lines.map((l) => `+${l}`).join("\n");
      const posixRel = rel.replace(/\\/g, "/");
      untrackedChunks.push(
        `diff --git a/${posixRel} b/${posixRel}\nnew file mode 100644\n--- /dev/null\n+++ b/${posixRel}\n@@ -0,0 +1,${lines.length} @@\n${plusBody}`
      );
      untrackedStatLines.push(` ${posixRel} (new untracked) | ${lines.length} +`);
      if (!changedFiles.includes(posixRel)) {
        changedFiles.push(posixRel);
      }
    } catch {
      // ignore unreadable untracked file
    }
  }

  if (untrackedChunks.length > 0) {
    rawDiff = [rawDiff, ...untrackedChunks].filter(Boolean).join("\n\n");
    statSummary = [statSummary, ...untrackedStatLines].filter(Boolean).join("\n");
  }

  if (!rawDiff) {
    rawDiff = safeGit(["show", "-U6", "--format=", "--ignore-space-at-eol", "HEAD"], cwd);
    statSummary = safeGit(["show", "--stat", "--format=", "HEAD"], cwd);
    const headFiles = safeGit(["show", "--name-only", "--format=", "HEAD"], cwd);
    changedFiles = headFiles
      .split(/\r?\n/)
      .map((line) => line.trim())
      .filter(Boolean);
  }

  const onlyMarkdownChanged =
    changedFiles.length > 0 && changedFiles.every((f) => f.toLowerCase().endsWith(".md"));
  if (onlyMarkdownChanged) {
    const headFiles = safeGit(["show", "--name-only", "--format=", "HEAD"], cwd)
      .split(/\r?\n/)
      .map((line) => line.trim())
      .filter(Boolean);
    if (headFiles.some((f) => !f.toLowerCase().endsWith(".md"))) {
      rawDiff = safeGit(["show", "-U6", "--format=", "--ignore-space-at-eol", "HEAD"], cwd) || rawDiff;
      statSummary = safeGit(["show", "--stat", "--format=", "HEAD"], cwd) || statSummary;
      changedFiles = headFiles;
    } else if (branch !== "main" && branch !== "master" && branch !== "HEAD") {
      const branchFilesRaw = safeGit(["diff", "main", "--name-only"], cwd);
      const branchFiles = branchFilesRaw
        .split(/\r?\n/)
        .map((line) => line.trim())
        .filter(Boolean);
      if (branchFiles.some((f) => !f.toLowerCase().endsWith(".md"))) {
        rawDiff = safeGit(["diff", "main", "-U6", "--ignore-space-at-eol"], cwd) || rawDiff;
        statSummary = safeGit(["diff", "main", "--stat"], cwd) || statSummary;
        changedFiles = branchFiles;
      }
    }
  } else if (rawDiff && rawDiff.length < 12000) {
    // When working tree has only a small follow-up edit right after a recent commit on HEAD,
    // include the recent HEAD commit diff if HEAD also modified non-markdown code files.
    const headEpochStr = safeGit(["log", "-1", "--format=%ct", "HEAD"], cwd);
    const headEpoch = Number(headEpochStr);
    const isRecentHead =
      Number.isFinite(headEpoch) &&
      headEpoch > 0 &&
      Math.abs(Date.now() / 1000 - headEpoch) <= 6 * 3600;
    if (isRecentHead) {
      const headFiles = safeGit(["show", "--name-only", "--format=", "HEAD"], cwd)
        .split(/\r?\n/)
        .map((line) => line.trim())
        .filter(Boolean);
      const headCodeFiles = headFiles.filter((f) => !f.toLowerCase().endsWith(".md"));
      if (headCodeFiles.length > 0) {
        const headDiff = safeGit(
          ["show", "-U4", "--format=", "--ignore-space-at-eol", "HEAD", "--", ...headCodeFiles],
          cwd
        );
        if (headDiff && headDiff !== rawDiff) {
          rawDiff = `${rawDiff}\n\n${headDiff}`;
          for (const hf of headCodeFiles) {
            if (!changedFiles.includes(hf)) {
              changedFiles.push(hf);
            }
          }
        }
      }
    }
  }

  if (changedFiles.length === 0 && statusShort) {
    changedFiles = statusShort
      .split(/\r?\n/)
      .map((line) => line.trim())
      .filter(Boolean)
      .map((line) => line.replace(/^[A-Z?]+\s+/, ""));
  }

  const rawStagedDiff = safeGit(["diff", "--cached", "--ignore-space-at-eol"], cwd);
  const stagedStat = safeGit(["diff", "--cached", "--stat"], cwd);

  const recentCommitsRaw = safeGit(["log", "-n", "8", "--oneline", "--no-decorate"], cwd);
  const recentCommits = recentCommitsRaw
    ? recentCommitsRaw.split(/\r?\n/).map((l) => l.trim()).filter(Boolean)
    : [];

  let branchCommitsSinceBase: string[] = [];
  if (branch !== "main" && branch !== "master" && branch !== "HEAD") {
    const branchLogRaw = safeGit(["log", "main..HEAD", "-n", "12", "--oneline", "--no-decorate"], cwd);
    if (branchLogRaw) {
      branchCommitsSinceBase = branchLogRaw.split(/\r?\n/).map((l) => l.trim()).filter(Boolean);
    }
  }

  return {
    isGitRepo: true,
    branch,
    statusShort: statusShort || `HEAD commit (${changedFiles.length} files)`,
    changedFiles,
    diff: budgetMultiFileDiff(rawDiff, statSummary, maxDiffChars),
    stagedDiff: budgetMultiFileDiff(rawStagedDiff, stagedStat, maxDiffChars),
    rawDiff: rawDiff || rawStagedDiff,
    recentCommits,
    branchCommitsSinceBase
  };
}
