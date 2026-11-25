import { execFileSync } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { readSessionEvents } from "./event-log.js";

export interface LearnedHumanOverride {
  id: string;
  createdAt: string;
  tool: string;
  feedbackType: "CORRECT" | "FALSE_POSITIVE_OVERRIDE" | "CUSTOM_RULE";
  rule: string;
  eventId?: string;
}

export interface PreFlightSyntaxReport {
  status: "PASS" | "SYNTAX_ERROR" | "SKIPPED";
  checkedFiles: string[];
  errors: string[];
}

export interface ProjectDnaEnvelope {
  workspaceName: string;
  workspacePath: string;
  stackSummary: string;
  repoTopology: string;
  domainAndAuthFingerprint?: string;
  projectRulesExcerpt?: string;
  activeMemoryExcerpt?: string;
  learnedHumanOverrides?: LearnedHumanOverride[];
  recentWorkspaceDecisions: Array<{
    timestamp: string;
    agent: string;
    tool: string;
    questionOrTitle: string;
    verdict: string;
    directive: string;
  }>;
}

export interface ReverseDependentsSummary {
  modifiedDependents: string[];
  unmodifiedDependents: string[];
  referencedTouchedSymbols: Record<string, string[]>;
}

export interface FileStructuralSummary {
  file: string;
  addedLines: number;
  removedLines: number;
  hunkHeaders: string[];
  touchedSymbols: string[];
}

export interface SpecRequirementMatch {
  id: string;
  requirement: string;
  matchedFiles: string[];
  matchedEvidence: string[];
}

interface CachedDnaEntry {
  expiresAt: number;
  dna: Omit<ProjectDnaEnvelope, "recentWorkspaceDecisions">;
}

const dnaCache = new Map<string, CachedDnaEntry>();
const DNA_CACHE_TTL_MS = 30_000;

const HOST_BINARY_DIR_NAMES = new Set([
  "antigravity",
  "programs",
  "system32",
  "windows",
  "appdata",
  "local"
]);

export function isGenericHostDirectory(dirPath: string): boolean {
  const normalized = path.resolve(dirPath).toLowerCase();
  const base = path.basename(normalized);
  if (HOST_BINARY_DIR_NAMES.has(base)) return true;
  if (normalized.includes("\\appdata\\local\\programs\\")) return true;
  return false;
}

function hasProjectRootMarker(dirPath: string): boolean {
  try {
    return (
      fs.existsSync(path.join(dirPath, ".git")) ||
      fs.existsSync(path.join(dirPath, "AGENTS.md")) ||
      fs.existsSync(path.join(dirPath, "GEMINI.md")) ||
      fs.existsSync(path.join(dirPath, "package.json")) ||
      fs.existsSync(path.join(dirPath, "pyproject.toml")) ||
      fs.existsSync(path.join(dirPath, "Cargo.toml")) ||
      fs.existsSync(path.join(dirPath, "go.mod"))
    );
  } catch {
    return false;
  }
}

function findNearestProjectRoot(startPath: string): string | undefined {
  try {
    let curr = path.resolve(startPath);
    if (fs.existsSync(curr) && fs.statSync(curr).isFile()) {
      curr = path.dirname(curr);
    }
    for (let depth = 0; depth < 7; depth++) {
      if (
        fs.existsSync(path.join(curr, ".git")) ||
        fs.existsSync(path.join(curr, "AGENTS.md")) ||
        fs.existsSync(path.join(curr, "package.json")) ||
        fs.existsSync(path.join(curr, "pyproject.toml"))
      ) {
        if (!isGenericHostDirectory(curr)) {
          return curr;
        }
      }
      const parent = path.dirname(curr);
      if (parent === curr) break;
      curr = parent;
    }
  } catch {
    // ignore filesystem errors
  }
  return undefined;
}

function extractRelativePathCandidates(texts: Array<string | undefined>): string[] {
  const results = new Set<string>();
  const relRegex =
    /(?:^|[\s"'`(\[:])((?:docs|src|apps|packages|backend|frontend|scripts|tests|ops|services|lib|components|pages|app|server|client|config)\/[A-Za-z0-9_./-]+\.[A-Za-z0-9]+|[A-Za-z0-9_.-]+\.(?:md|ts|tsx|js|jsx|py|go|json|yaml|yml|toml|sh|ps1|css|sql))(?:$|[\s"'`)\]:,;])/gm;

  for (const text of texts) {
    if (!text) continue;
    for (const match of text.matchAll(relRegex)) {
      const candidate = match[1]?.trim().replace(/^[./\\]+/, "");
      if (candidate && candidate.length > 2 && !candidate.startsWith("http")) {
        results.add(candidate);
      }
    }
  }
  return Array.from(results);
}

/**
 * Blocks secret/credential files from ever being auto-read and uploaded to an external API.
 */
export function isSensitiveFilePath(filePath: string): boolean {
  const normalized = filePath.replace(/\\/g, "/").toLowerCase();
  const base = path.posix.basename(normalized);
  if (
    base === ".env.example" ||
    base === ".env.sample" ||
    base === ".env.template" ||
    base === ".env.dist"
  ) {
    return false;
  }
  if (
    base === ".env" ||
    base.startsWith(".env.") ||
    base === ".npmrc" ||
    base === ".netrc" ||
    base === ".pypirc" ||
    base === "id_rsa" ||
    base === "id_ed25519" ||
    base === "id_ecdsa" ||
    base === "credentials.json" ||
    normalized.includes("/.mcp-jev/config.json") ||
    normalized.includes("/.ssh/") ||
    normalized.includes("/.aws/") ||
    /\.(pem|key|p12|pfx|keystore|jks)$/i.test(base)
  ) {
    return true;
  }
  return false;
}

/**
 * Ensures `targetPath` resolves strictly inside `workspaceRoot` (preventing `../` traversal or symlink escape).
 */
export function isWithinWorkspaceBoundary(workspaceRoot: string, targetPath: string): boolean {
  try {
    const resolvedRoot = fs.existsSync(workspaceRoot)
      ? fs.realpathSync(workspaceRoot)
      : path.resolve(workspaceRoot);
    const resolvedTarget = fs.existsSync(targetPath)
      ? fs.realpathSync(targetPath)
      : path.resolve(targetPath);
    const rel = path.relative(resolvedRoot, resolvedTarget);
    if (rel === "") return true;
    if (rel.startsWith("..") || path.isAbsolute(rel)) return false;
    if (process.platform === "win32") {
      return resolvedTarget.toLowerCase().startsWith(`${resolvedRoot.toLowerCase()}${path.sep}`);
    }
    return true;
  } catch {
    return false;
  }
}

export function isSafeReadableWorkspaceFile(workspaceRoot: string, targetPath: string): boolean {
  return !isSensitiveFilePath(targetPath) && isWithinWorkspaceBoundary(workspaceRoot, targetPath);
}

let cachedPythonBin: string | null = null;

/**
 * Cross-platform Python binary resolver (`python3` preferred on POSIX, `python` on Windows).
 */
export function resolvePythonExecutable(): string {
  if (cachedPythonBin) return cachedPythonBin;
  const candidates =
    process.platform === "win32" ? ["python", "python3"] : ["python3", "python"];
  for (const bin of candidates) {
    try {
      execFileSync(bin, ["--version"], {
        timeout: 600,
        stdio: ["ignore", "ignore", "ignore"]
      });
      cachedPythonBin = bin;
      return bin;
    } catch {
      // try next candidate
    }
  }
  cachedPythonBin = process.platform === "win32" ? "python" : "python3";
  return cachedPythonBin;
}

/**
 * Resolves the true target project workspace even when the calling agent omits `working_directory`
 * or when `process.cwd()` points to a generic IDE host directory (e.g. `.../Programs/Antigravity`).
 */
export function resolveTargetWorkspace(
  explicitCwd?: string,
  hints: Array<string | undefined> = []
): string {
  // 1. If explicitCwd is provided and is a real project directory (not IDE host dir), prefer it
  if (explicitCwd && explicitCwd.trim().length > 0 && !isGenericHostDirectory(explicitCwd)) {
    const resolved = path.resolve(explicitCwd);
    const root = findNearestProjectRoot(resolved);
    if (root) return root;
    if (fs.existsSync(resolved)) return resolved;
  }

  // 2. Scan hints for any absolute Windows or POSIX workspace paths on disk
  const absPathRegexes = [
    /\b([A-Za-z]:[\\/][^\s"'`<>|?*]+)\b/g,
    /(?:^|[\s"'`(\[])(\/(?:Users|home|workspace|workspaces|projects|srv|opt|var\/www)\/[^\s"'`<>|?*]+)/g
  ];
  for (const hint of hints) {
    if (!hint) continue;
    for (const rx of absPathRegexes) {
      for (const match of hint.matchAll(rx)) {
        const rawPath = match[1].replace(/[,:;.)\]'"]+$/, "");
        const root = findNearestProjectRoot(rawPath);
        if (root) return root;
      }
    }
  }

  // Gather known active workspaces from recent session events + configured/sibling parent roots
  const recentEvents = readSessionEvents(60);
  const candidateWorkspaces: string[] = [];
  for (const ev of recentEvents) {
    if (
      ev.workspacePath &&
      !isGenericHostDirectory(ev.workspacePath) &&
      !candidateWorkspaces.includes(ev.workspacePath) &&
      fs.existsSync(ev.workspacePath) &&
      hasProjectRootMarker(ev.workspacePath)
    ) {
      candidateWorkspaces.push(ev.workspacePath);
    }
  }

  const configuredRoots = (process.env.JEV_WORKSPACE_ROOTS ?? "")
    .split(path.delimiter)
    .map((s) => s.trim())
    .filter(Boolean);
  const procCwd = process.cwd();
  if (!isGenericHostDirectory(procCwd)) {
    const parentDir = path.dirname(path.resolve(procCwd));
    if (parentDir && parentDir !== path.parse(parentDir).root && !isGenericHostDirectory(parentDir)) {
      configuredRoots.push(parentDir);
    }
  }

  for (const rootDir of configuredRoots) {
    try {
      if (!fs.existsSync(rootDir)) continue;
      for (const entry of fs.readdirSync(rootDir, { withFileTypes: true }).slice(0, 60)) {
        if (entry.isDirectory()) {
          const full = path.join(rootDir, entry.name);
          if (!candidateWorkspaces.includes(full) && hasProjectRootMarker(full)) {
            candidateWorkspaces.push(full);
          }
        }
      }
    } catch {
      // ignore
    }
  }

  // 3. Check if relative file paths mentioned in hints exist inside one of the candidate workspaces
  const relCandidates = extractRelativePathCandidates(hints);
  if (relCandidates.length > 0) {
    let bestWorkspace: string | undefined;
    let bestScore = 0;
    for (const wsPath of candidateWorkspaces) {
      let score = 0;
      for (const rel of relCandidates.slice(0, 16)) {
        if (fs.existsSync(path.join(wsPath, rel))) {
          score += 1;
        }
      }
      if (score > bestScore) {
        bestScore = score;
        bestWorkspace = wsPath;
      }
    }
    if (bestWorkspace && bestScore > 0) {
      return bestWorkspace;
    }
  }

  // 4. Check if any hint explicitly names a known workspace folder
  const primaryHintsLower = hints
    .filter(Boolean)
    .map((h) => h!.slice(0, 1200))
    .join("\n")
    .toLowerCase();
  for (const wsPath of candidateWorkspaces) {
    const wsName = path.basename(wsPath).toLowerCase();
    if (wsName.length < 4) continue;
    const escaped = wsName.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    const boundaryRegex = new RegExp(`(?:^|[\\s"'\\(\\[/\\\\])${escaped}(?:$|[\\s"'\\)\\]/\\\\.,:;])`, "i");
    if (boundaryRegex.test(primaryHintsLower)) {
      return wsPath;
    }
  }

  // 5. If process.cwd() is a valid non-host workspace, use it; otherwise fallback to most recent valid workspace
  if (!isGenericHostDirectory(procCwd)) {
    return path.resolve(procCwd);
  }

  return candidateWorkspaces[0] ?? path.resolve(procCwd);
}

function safeReadText(filePath: string, maxChars = 1500): string | undefined {
  try {
    if (!fs.existsSync(filePath)) return undefined;
    const stat = fs.statSync(filePath);
    if (!stat.isFile()) return undefined;
    const raw = fs.readFileSync(filePath, "utf8").trim();
    if (!raw) return undefined;
    return raw.length <= maxChars ? raw : `${raw.slice(0, maxChars)}\n...[TRUNCATED]`;
  } catch {
    return undefined;
  }
}

/**
 * Distills markdown documentation by keeping headings, critical directives (MUST/NEVER/BẮT BUỘC),
 * and structural bullet points so multiple doc files fit into a compact high-signal envelope.
 */
function distillMarkdownDoc(filePath: string, maxChars = 1200): string | undefined {
  try {
    if (!fs.existsSync(filePath) || !fs.statSync(filePath).isFile()) return undefined;
    const raw = fs.readFileSync(filePath, "utf8").trim();
    if (!raw) return undefined;
    if (raw.length <= maxChars) return raw;

    const lines = raw.split(/\r?\n/);
    const prioritized: string[] = [];
    let currentLen = 0;

    for (const line of lines) {
      const trimmed = line.trim();
      if (!trimmed) continue;
      const isHighSignal =
        /^#{1,4}\s+/.test(trimmed) ||
        /\b(MUST|NEVER|ALWAYS|IMPORTANT|CRITICAL|BẮT BUỘC|KHÔNG ĐƯỢC|ƯU TIÊN|INVARIANT|GATE|SECURITY|ARCHITECTURE|STACK)\b/i.test(
          trimmed
        ) ||
        /^[-*]\s+\*\*[^*]+\*\*/.test(trimmed);

      if (isHighSignal || currentLen < maxChars * 0.45) {
        if (currentLen + trimmed.length + 1 > maxChars) break;
        prioritized.push(trimmed);
        currentLen += trimmed.length + 1;
      }
    }

    return prioritized.length > 0
      ? prioritized.join("\n")
      : `${raw.slice(0, maxChars)}\n...[TRUNCATED]`;
  } catch {
    return undefined;
  }
}

function summarizePackageJson(pkgPath: string, rootCwd: string): string | undefined {
  try {
    if (!fs.existsSync(pkgPath)) return undefined;
    const raw = JSON.parse(fs.readFileSync(pkgPath, "utf8")) as {
      name?: string;
      dependencies?: Record<string, string>;
      devDependencies?: Record<string, string>;
      scripts?: Record<string, string>;
    };
    const deps = [
      ...Object.keys(raw.dependencies ?? {}),
      ...Object.keys(raw.devDependencies ?? {})
    ].slice(0, 22);
    const scripts = Object.keys(raw.scripts ?? {}).slice(0, 8);
    const relDir = path.relative(rootCwd, path.dirname(pkgPath)) || ".";
    return `${raw.name ?? relDir} (${relDir}): deps=[${deps.join(", ")}]${scripts.length > 0 ? ` scripts=[${scripts.join(", ")}]` : ""}`;
  } catch {
    return undefined;
  }
}

function discoverSubdirPackages(baseDir: string): string[] {
  try {
    if (!fs.existsSync(baseDir)) return [];
    return fs
      .readdirSync(baseDir, { withFileTypes: true })
      .filter((d) => d.isDirectory())
      .map((d) => path.join(baseDir, d.name, "package.json"))
      .filter((p) => fs.existsSync(p));
  } catch {
    return [];
  }
}

function buildStackSummary(cwd: string): string {
  const parts: string[] = [];
  const candidatePkgPaths = [
    path.join(cwd, "package.json"),
    path.join(cwd, "frontend", "package.json"),
    ...discoverSubdirPackages(path.join(cwd, "apps")),
    ...discoverSubdirPackages(path.join(cwd, "packages"))
  ];

  const seen = new Set<string>();
  for (const pkgPath of candidatePkgPaths) {
    if (seen.has(pkgPath)) continue;
    seen.add(pkgPath);
    const summary = summarizePackageJson(pkgPath, cwd);
    if (summary) parts.push(summary);
  }

  const pyProjectCandidates = [
    path.join(cwd, "pyproject.toml"),
    path.join(cwd, "backend", "pyproject.toml"),
    path.join(cwd, "requirements.txt"),
    path.join(cwd, "backend", "requirements.txt")
  ];
  for (const pyPath of pyProjectCandidates) {
    const excerpt = safeReadText(pyPath, 500);
    if (excerpt) {
      parts.push(
        `${path.relative(cwd, pyPath) || path.basename(pyPath)}: ${excerpt.replace(/\s+/g, " ")}`
      );
      break;
    }
  }

  return parts.length > 0 ? parts.join(" | ").slice(0, 1800) : "generic workspace";
}

function buildRepoTopology(cwd: string): string {
  const ignored = new Set([
    ".git",
    "node_modules",
    "dist",
    "build",
    ".next",
    ".turbo",
    "__pycache__",
    ".venv",
    "venv",
    ".pytest_cache",
    "coverage",
    ".codegraph"
  ]);
  try {
    const entries = fs.readdirSync(cwd, { withFileTypes: true });
    const topItems: string[] = [];
    for (const entry of entries) {
      if (ignored.has(entry.name) || entry.name.startsWith(".")) continue;
      if (entry.isDirectory()) {
        try {
          const children = fs
            .readdirSync(path.join(cwd, entry.name), { withFileTypes: true })
            .filter((c) => !ignored.has(c.name) && !c.name.startsWith("."))
            .slice(0, 8)
            .map((c) => (c.isDirectory() ? `${c.name}/` : c.name));
          topItems.push(
            children.length > 0 ? `${entry.name}/[${children.join(", ")}]` : `${entry.name}/`
          );
        } catch {
          topItems.push(`${entry.name}/`);
        }
      } else {
        topItems.push(entry.name);
      }
    }
    return topItems.slice(0, 24).join(", ");
  } catch {
    return "";
  }
}

export function buildProjectContextEnvelope(
  cwd: string = process.cwd(),
  hints: Array<string | undefined> = []
): ProjectDnaEnvelope {
  const resolvedCwd = resolveTargetWorkspace(cwd, hints);
  const workspaceName = path.basename(resolvedCwd) || "workspace";
  const now = Date.now();

  let baseDna = dnaCache.get(resolvedCwd)?.dna;
  if (!baseDna || (dnaCache.get(resolvedCwd)?.expiresAt ?? 0) < now) {
    // Combine ALL present rule & architecture documents instead of stopping after the first file
    const ruleCandidates: Array<{ file: string; budget: number }> = [
      { file: "AGENTS.md", budget: 1400 },
      { file: "CLAUDE.md", budget: 900 },
      { file: "GEMINI.md", budget: 900 },
      { file: "CONTEXT.md", budget: 1100 },
      { file: "PRODUCT.md", budget: 1000 },
      { file: "ARCHITECTURE.md", budget: 1000 },
      { file: "README.md", budget: 800 }
    ];
    const ruleSections: string[] = [];
    let totalRuleChars = 0;
    for (const { file, budget } of ruleCandidates) {
      if (totalRuleChars >= 3400) break;
      const text = distillMarkdownDoc(path.join(resolvedCwd, file), budget);
      if (text) {
        ruleSections.push(`[${file}]\n${text}`);
        totalRuleChars += text.length;
      }
    }
    const projectRulesExcerpt =
      ruleSections.length > 0 ? ruleSections.join("\n\n").slice(0, 3600) : undefined;

    // Combine BOTH CURRENT.md and WORKBOARD.md when present
    const memoryCandidates = [
      { rel: path.join("docs", "memory", "CURRENT.md"), budget: 1100 },
      { rel: path.join("docs", "memory", "WORKBOARD.md"), budget: 900 }
    ];
    const memorySections: string[] = [];
    for (const { rel, budget } of memoryCandidates) {
      const text = distillMarkdownDoc(path.join(resolvedCwd, rel), budget);
      if (text) {
        memorySections.push(`[${rel.replace(/\\/g, "/")}]\n${text}`);
      }
    }
    const activeMemoryExcerpt =
      memorySections.length > 0 ? memorySections.join("\n\n").slice(0, 2000) : undefined;

    baseDna = {
      workspaceName,
      workspacePath: resolvedCwd,
      stackSummary: buildStackSummary(resolvedCwd),
      repoTopology: buildRepoTopology(resolvedCwd),
      domainAndAuthFingerprint: extractDomainAndRuntimeFingerprint(resolvedCwd),
      projectRulesExcerpt,
      activeMemoryExcerpt
    };
    dnaCache.set(resolvedCwd, {
      expiresAt: now + DNA_CACHE_TTL_MS,
      dna: baseDna
    });
    syncProjectBrainProfile({
      ...baseDna,
      recentWorkspaceDecisions: []
    });
  }

  const recentEvents = readSessionEvents(40)
    .filter((e) => e.workspace.toLowerCase() === workspaceName.toLowerCase())
    .slice(0, 5)
    .map((e) => ({
      timestamp: e.timestamp,
      agent: e.agent,
      tool: e.tool,
      questionOrTitle: e.questionOrTitle.slice(0, 220),
      verdict: e.verdict,
      directive: e.directive.slice(0, 220)
    }));

  return {
    ...baseDna,
    learnedHumanOverrides: readLearnedHumanOverrides(workspaceName),
    recentWorkspaceDecisions: recentEvents
  };
}

/**
 * Automatically detects and reads any files (handoffs, review docs, specs, scripts, components)
 * explicitly referenced inside the prompt/spec/question/context so Jev never evaluates blindly.
 */
export function extractReferencedDocsAndFiles(
  cwd: string,
  texts: Array<string | undefined>,
  maxFiles = 5,
  maxCharsPerFile = 2400
): Record<string, string> {
  const resolvedCwd = path.resolve(cwd);
  const candidates = extractRelativePathCandidates(texts);
  const combinedPrompt = texts.filter(Boolean).join("\n");

  // Extract specific section/ticket tokens mentioned in the prompt (e.g. CR1-01, R1, Phase 2)
  const focusTokens = Array.from(
    new Set(
      Array.from(
        combinedPrompt.matchAll(/\b([A-Z]{2,5}\d*-\d+|section\s+\d+|pha(?:se)?\s+\d+)\b/gi),
        (m) => m[1].toLowerCase()
      )
    )
  );

  const result: Record<string, string> = {};
  for (const rel of candidates) {
    if (Object.keys(result).length >= maxFiles) break;
    const fullPath = path.isAbsolute(rel) ? rel : path.join(resolvedCwd, rel);
    if (isSensitiveFilePath(fullPath) || !isWithinWorkspaceBoundary(resolvedCwd, fullPath)) {
      continue;
    }
    try {
      if (!fs.existsSync(fullPath) || !fs.statSync(fullPath).isFile()) continue;
      const raw = fs.readFileSync(fullPath, "utf8").trim();
      if (!raw) continue;

      if (raw.length <= maxCharsPerFile) {
        result[rel] = raw;
        continue;
      }

      // If prompt mentions specific IDs/sections (like CR1-01..CR1-03), pull header + matching sections
      const lines = raw.split(/\r?\n/);
      const head = lines.slice(0, 35).join("\n");
      const matchedSnippets: string[] = [];

      if (focusTokens.length > 0) {
        for (let i = 35; i < lines.length; i++) {
          const lower = lines[i].toLowerCase();
          if (focusTokens.some((tok) => lower.includes(tok))) {
            const block = lines.slice(Math.max(35, i - 2), Math.min(lines.length, i + 18)).join("\n");
            matchedSnippets.push(block);
            i += 15;
            if (matchedSnippets.join("\n").length > maxCharsPerFile * 0.6) break;
          }
        }
      }

      if (matchedSnippets.length > 0) {
        result[rel] = `${head}\n...\n${matchedSnippets.join("\n---\n")}`.slice(0, maxCharsPerFile);
      } else {
        result[rel] = `${raw.slice(0, maxCharsPerFile)}\n...[TRUNCATED]`;
      }
    } catch {
      // ignore unreadable files
    }
  }

  return result;
}

/**
 * Parses the full raw git diff BEFORE character truncation to produce a complete
 * per-file structural map (line counts, hunk headers, and added/modified symbols,
 * functions, components, tests, routes, and CSS selectors).
 */
export function extractStructuralDiffMap(rawDiff: string): FileStructuralSummary[] {
  if (!rawDiff || !rawDiff.trim()) return [];
  const chunks = rawDiff
    .split(/(?=^diff --git )/m)
    .map((c) => c.trim())
    .filter(Boolean);

  const results: FileStructuralSummary[] = [];
  const symbolRegex =
    /^\+\s*(?:export\s+)?(?:default\s+)?(?:async\s+)?(?:function|class|interface|type|const|let|def|describe|it|test)\s+([A-Za-z0-9_$]+)|^\+\s*([.#][a-zA-Z0-9_-]+)\s*\{|^\+\s*@(?:app|router)\.(?:get|post|put|delete|patch)\(\s*["']([^"']+)["']/;

  for (const chunk of chunks.slice(0, 45)) {
    const fileMatch =
      chunk.match(/^diff --git a\/.+? b\/([^\r\n\t]+)$/m) ??
      chunk.match(/^\+\+\+ b\/([^\r\n\t]+)$/m);
    const file = fileMatch ? fileMatch[1].trim() : "unknown";

    let addedLines = 0;
    let removedLines = 0;
    const hunkHeaders: string[] = [];
    const touchedSymbols: string[] = [];

    const lines = chunk.split(/\r?\n/);
    for (const line of lines) {
      if (line.startsWith("@@")) {
        const hunkCtx = line.replace(/^@@[^@]+@@\s*/, "").trim();
        if (hunkCtx && hunkHeaders.length < 10 && !hunkHeaders.includes(hunkCtx)) {
          hunkHeaders.push(hunkCtx.slice(0, 100));
        }
        continue;
      }
      if (line.startsWith("+") && !line.startsWith("+++")) {
        addedLines += 1;
        if (touchedSymbols.length < 18) {
          const symMatch = line.match(symbolRegex);
          const sym = symMatch?.[1] ?? symMatch?.[2] ?? symMatch?.[3];
          if (sym && !touchedSymbols.includes(sym)) {
            touchedSymbols.push(sym);
          }
        }
      } else if (line.startsWith("-") && !line.startsWith("---")) {
        removedLines += 1;
      }
    }

    results.push({
      file,
      addedLines,
      removedLines,
      hunkHeaders,
      touchedSymbols
    });
  }

  return results;
}

/**
 * Reads the actual post-edit files on disk around the modified hunk line numbers (`@@ ... +start,count @@`)
 * and locates the nearest enclosing function/class/route decorator header above each hunk.
 * This gives Jev the true post-edit code structure and surrounding guards/transactions/auth decorators.
 */
export function extractPostEditHunkScopes(
  cwd: string,
  rawDiff: string,
  maxFiles = 6,
  maxTotalChars = 7500
): Record<string, string> {
  if (!rawDiff || !rawDiff.trim()) return {};
  const resolvedCwd = path.resolve(cwd);
  const chunks = rawDiff
    .split(/(?=^diff --git )/m)
    .map((c) => c.trim())
    .filter(Boolean);

  const scopes: Record<string, string> = {};
  let usedChars = 0;
  const sigRegex =
    /^\s*(?:export\s+)?(?:default\s+)?(?:async\s+)?(?:function\s+[A-Za-z0-9_$]+|class\s+[A-Za-z0-9_$]+|const\s+[A-Za-z0-9_$]+\s*=\s*(?:async\s*)?\(|def\s+[A-Za-z0-9_]+|async\s+def\s+[A-Za-z0-9_]+|@(?:app|router)\.(?:get|post|put|delete|patch))/;

  for (const chunk of chunks) {
    if (Object.keys(scopes).length >= maxFiles || usedChars >= maxTotalChars) break;
    const fileMatch =
      chunk.match(/^diff --git a\/.+? b\/([^\r\n\t]+)$/m) ??
      chunk.match(/^\+\+\+ b\/([^\r\n\t]+)$/m);
    const relFile = fileMatch ? fileMatch[1].trim() : "";
    if (!relFile || !/\.(ts|tsx|js|jsx|mjs|py|go|css)$/i.test(relFile)) continue;

    const fullPath = path.join(resolvedCwd, relFile);
    if (!isSafeReadableWorkspaceFile(resolvedCwd, fullPath) || !fs.existsSync(fullPath)) continue;

    try {
      const fileLines = fs.readFileSync(fullPath, "utf8").split(/\r?\n/);
      const hunkMatches = Array.from(
        chunk.matchAll(/^@@\s*-\d+(?:,\d+)?\s+\+(\d+)(?:,(\d+))?\s*@@/gm)
      );
      if (hunkMatches.length === 0) continue;

      const windows: Array<{ start: number; end: number; enclosingHeader?: string }> = [];
      for (const m of hunkMatches.slice(0, 3)) {
        const startLine = Math.max(1, parseInt(m[1], 10));
        const count = m[2] !== undefined ? parseInt(m[2], 10) : 1;
        const winStart = Math.max(1, startLine - 10);
        const winEnd = Math.min(fileLines.length, startLine + Math.max(1, count) + 10);

        // Search upward from winStart for the enclosing function/class/decorator header
        let enclosingHeader: string | undefined;
        for (let lineIdx = winStart - 2; lineIdx >= Math.max(0, winStart - 60); lineIdx--) {
          if (sigRegex.test(fileLines[lineIdx])) {
            enclosingHeader = `L${lineIdx + 1}: ${fileLines[lineIdx].trim()}`;
            break;
          }
        }
        windows.push({ start: winStart, end: winEnd, enclosingHeader });
      }

      const formattedBlocks = windows.map((w) => {
        const numbered = fileLines
          .slice(w.start - 1, w.end)
          .map((l, idx) => `L${w.start + idx}: ${l}`)
          .join("\n");
        return w.enclosingHeader
          ? `[Enclosing Scope -> ${w.enclosingHeader}]\n${numbered}`
          : numbered;
      });

      const combined = formattedBlocks.join("\n...\n").slice(0, 1600);
      if (combined) {
        scopes[relFile] = combined;
        usedChars += combined.length;
      }
    } catch {
      // ignore read errors
    }
  }

  return scopes;
}

function resolveRelativeImportPath(fromFileFull: string, importSpec: string, rootCwd: string): string | undefined {
  const baseDir = path.dirname(fromFileFull);
  const candidates: string[] = [];

  if (importSpec.startsWith(".")) {
    const rawTarget = path.resolve(baseDir, importSpec.replace(/\.(js|mjs)$/, ""));
    candidates.push(
      rawTarget,
      `${rawTarget}.ts`,
      `${rawTarget}.tsx`,
      `${rawTarget}.js`,
      `${rawTarget}.py`,
      path.join(rawTarget, "index.ts"),
      path.join(rawTarget, "index.tsx")
    );
  } else if (importSpec.startsWith("@/")) {
    const stripped = importSpec.slice(2).replace(/\.(js|mjs)$/, "");
    for (const prefix of ["src", "frontend/src", "apps/web/src", "apps/api/src"]) {
      const target = path.join(rootCwd, prefix, stripped);
      candidates.push(target, `${target}.ts`, `${target}.tsx`, path.join(target, "index.ts"));
    }
  } else if (/^(?:app|backend\.app)\./.test(importSpec)) {
    const relPy = importSpec.replace(/^backend\./, "").replace(/\./g, "/");
    candidates.push(
      path.join(rootCwd, `${relPy}.py`),
      path.join(rootCwd, "backend", `${relPy}.py`),
      path.join(rootCwd, relPy, "__init__.py"),
      path.join(rootCwd, "backend", relPy, "__init__.py")
    );
  }

  for (const c of candidates) {
    if (fs.existsSync(c) && fs.statSync(c).isFile()) {
      return c;
    }
  }
  return undefined;
}

/**
 * Resolves local cross-file imports (`./...`, `../...`, `@/...`, `from app... import ...`)
 * from modified files and extracts exported TypeScript interfaces/types/schemas and Python Pydantic/function signatures.
 * Also queries `.codegraph` if initialized in the workspace.
 */
export function extractCrossFileContracts(
  cwd: string,
  changedFiles: string[],
  maxContracts = 6,
  maxTotalChars = 4800
): Record<string, string> {
  const resolvedCwd = path.resolve(cwd);
  const contracts: Record<string, string> = {};
  let totalChars = 0;

  const tsImportRegex = /from\s+["'](\.[^"']+|@\/[^"']+)["']/g;
  const pyImportRegex = /^\s*from\s+((?:app|backend\.app)\.[A-Za-z0-9_.]+)\s+import\s+/gm;
  const exportLineRegex =
    /^\s*(?:export\s+(?:interface|type|enum|class|function|async\s+function|const)\s+[A-Za-z0-9_$]+.*|class\s+[A-Za-z0-9_]+\([^)]*\):|(?:async\s+)?def\s+[A-Za-z0-9_]+\([^)]*\).*?:)/;

  const visitedTargets = new Set<string>();

  for (const relFile of changedFiles.slice(0, 8)) {
    if (Object.keys(contracts).length >= maxContracts || totalChars >= maxTotalChars) break;
    const fullFrom = path.isAbsolute(relFile) ? relFile : path.join(resolvedCwd, relFile);
    if (
      !isSafeReadableWorkspaceFile(resolvedCwd, fullFrom) ||
      !fs.existsSync(fullFrom) ||
      !fs.statSync(fullFrom).isFile()
    ) {
      continue;
    }

    try {
      const source = fs.readFileSync(fullFrom, "utf8").slice(0, 8000);
      const importSpecs: string[] = [];
      for (const m of source.matchAll(tsImportRegex)) {
        if (m[1]) importSpecs.push(m[1]);
      }
      for (const m of source.matchAll(pyImportRegex)) {
        if (m[1]) importSpecs.push(m[1]);
      }

      for (const spec of importSpecs) {
        if (Object.keys(contracts).length >= maxContracts || totalChars >= maxTotalChars) break;
        const resolvedTarget = resolveRelativeImportPath(fullFrom, spec, resolvedCwd);
        if (
          !resolvedTarget ||
          visitedTargets.has(resolvedTarget) ||
          !isSafeReadableWorkspaceFile(resolvedCwd, resolvedTarget)
        ) {
          continue;
        }
        visitedTargets.add(resolvedTarget);

        const targetLines = fs.readFileSync(resolvedTarget, "utf8").split(/\r?\n/);
        const extracted: string[] = [];
        for (let i = 0; i < targetLines.length && extracted.join("\n").length < 900; i++) {
          if (exportLineRegex.test(targetLines[i])) {
            const block = targetLines.slice(i, Math.min(targetLines.length, i + 8)).join("\n");
            extracted.push(block);
            i += 6;
          }
        }

        if (extracted.length > 0) {
          const relTarget = path.relative(resolvedCwd, resolvedTarget).replace(/\\/g, "/");
          const snippet = extracted.join("\n").slice(0, 950);
          contracts[relTarget] = snippet;
          totalChars += snippet.length;
        }
      }
    } catch {
      // ignore
    }
  }

  // Optional CodeGraph CLI enrichment when `.codegraph` exists in the workspace
  if (fs.existsSync(path.join(resolvedCwd, ".codegraph")) && changedFiles.length > 0) {
    try {
      const queryTerm = path.basename(changedFiles[0], path.extname(changedFiles[0]));
      if (/^[A-Za-z0-9_.-]+$/.test(queryTerm) && !queryTerm.startsWith("-")) {
        const winNpmCodegraphJs =
          process.platform === "win32" && process.env.APPDATA
            ? path.join(
                process.env.APPDATA,
                "npm",
                "node_modules",
                "@colbymchenry",
                "codegraph",
                "dist",
                "bin",
                "codegraph.js"
              )
            : undefined;
        const useNodeJsRunner = Boolean(winNpmCodegraphJs && fs.existsSync(winNpmCodegraphJs));
        const cgOut = execFileSync(
          useNodeJsRunner ? process.execPath : "codegraph",
          useNodeJsRunner ? [winNpmCodegraphJs!, "query", queryTerm] : ["query", queryTerm],
          {
            cwd: resolvedCwd,
            encoding: "utf8",
            timeout: 1200,
            stdio: ["ignore", "pipe", "ignore"]
          }
        ).trim();
        if (cgOut) {
          contracts["[codegraph_symbol_relations]"] = cgOut.slice(0, 900);
        }
      }
    } catch {
      // non-fatal if codegraph binary is not in PATH or times out
    }
  }

  return contracts;
}

/**
 * Splits multi-point specifications (e.g., `(1) ... (2) ...` or `1. ... 2. ...` or bulleted lists)
 * into discrete requirement items and pre-maps each requirement against changed files and touched symbols.
 */
export function buildSpecRequirementMatrix(
  spec: string,
  structuralMap: FileStructuralSummary[],
  rawDiff: string
): SpecRequirementMatch[] {
  if (!spec || !spec.trim()) return [];

  // Split by numbered items `(1)`, `1.`, `1)` or markdown bullets or semicolons when multi-clause
  const rawSegments = spec
    .split(/(?:\r?\n)+\s*(?:[-*•]|\(?\d+[.)])\s+|\s+\(\d+\)\s+/g)
    .map((s) => s.trim())
    .filter((s) => s.length >= 8);

  const segments =
    rawSegments.length > 1
      ? rawSegments
      : spec
          .split(/\s*;\s+/g)
          .map((s) => s.trim())
          .filter((s) => s.length >= 12);

  const stopWords = new Set([
    "the",
    "and",
    "for",
    "with",
    "from",
    "that",
    "this",
    "into",
    "when",
    "only",
    "must",
    "should",
    "keep",
    "make",
    "update",
    "add",
    "fix",
    "trong",
    "các",
    "của",
    "cho",
    "không",
    "được",
    "với",
    "khi",
    "nhưng",
    "phải",
    "thêm",
    "sửa"
  ]);

  const addedLinesLower = rawDiff
    .split(/\r?\n/)
    .filter((l) => l.startsWith("+") && !l.startsWith("+++"))
    .join("\n")
    .toLowerCase();

  return segments.slice(0, 12).map((reqText, idx) => {
    const tokens = Array.from(
      new Set(
        reqText
          .split(/[^A-Za-z0-9_./-]+/)
          .map((t) => t.trim())
          .filter((t) => t.length >= 3 && !stopWords.has(t.toLowerCase()))
      )
    );

    const matchedFiles: string[] = [];
    const matchedEvidence: string[] = [];

    for (const fileEntry of structuralMap) {
      const fileLower = fileEntry.file.toLowerCase();
      const symbolsLower = fileEntry.touchedSymbols.map((s) => s.toLowerCase());
      const hunksLower = fileEntry.hunkHeaders.join(" ").toLowerCase();

      for (const tok of tokens) {
        const tokLower = tok.toLowerCase();
        if (fileLower.includes(tokLower)) {
          if (!matchedFiles.includes(fileEntry.file)) matchedFiles.push(fileEntry.file);
        }
        for (let sIdx = 0; sIdx < symbolsLower.length; sIdx++) {
          if (symbolsLower[sIdx].includes(tokLower) || tokLower.includes(symbolsLower[sIdx])) {
            if (!matchedFiles.includes(fileEntry.file)) matchedFiles.push(fileEntry.file);
            const ev = `${fileEntry.file}#${fileEntry.touchedSymbols[sIdx]}`;
            if (!matchedEvidence.includes(ev)) matchedEvidence.push(ev);
          }
        }
        if (hunksLower.includes(tokLower) && !matchedFiles.includes(fileEntry.file)) {
          matchedFiles.push(fileEntry.file);
        }
      }
    }

    if (matchedEvidence.length === 0) {
      for (const tok of tokens) {
        if (tok.length >= 4 && addedLinesLower.includes(tok.toLowerCase())) {
          matchedEvidence.push(`diff:+${tok}`);
          if (matchedEvidence.length >= 5) break;
        }
      }
    }

    return {
      id: `REQ_${idx + 1}`,
      requirement: reqText.slice(0, 240),
      matchedFiles: matchedFiles.slice(0, 6),
      matchedEvidence: matchedEvidence.slice(0, 6)
    };
  });
}

/**
 * Extracts the top imports, auth middleware, and validation schema headers of modified files
 * so `jev_audit_code` does not false-flag partial diffs whose imports/validators sit at the top of the file.
 */
export function extractFileHeaderContext(
  cwd: string,
  filePath?: string,
  changedFiles: string[] = []
): Record<string, string> {
  const resolvedCwd = path.resolve(cwd);
  const targets: string[] = [];
  if (filePath && filePath !== "local git diff" && filePath !== "unknown") {
    targets.push(filePath);
  }
  for (const f of changedFiles) {
    if (targets.length >= 5) break;
    if (!targets.includes(f) && /\.(ts|tsx|js|jsx|mjs|py|go)$/i.test(f)) {
      targets.push(f);
    }
  }

  const headers: Record<string, string> = {};
  for (const relOrAbs of targets) {
    const fullPath = path.isAbsolute(relOrAbs)
      ? relOrAbs
      : path.join(resolvedCwd, relOrAbs);
    if (!isSafeReadableWorkspaceFile(resolvedCwd, fullPath)) {
      continue;
    }
    try {
      if (!fs.existsSync(fullPath) || !fs.statSync(fullPath).isFile()) continue;
      const lines = fs
        .readFileSync(fullPath, "utf8")
        .split(/\r?\n/)
        .slice(0, 55)
        .join("\n")
        .trim();
      if (lines) {
        headers[relOrAbs] = lines.slice(0, 1800);
      }
    } catch {
      // ignore unreadable files
    }
  }
  return headers;
}

const repoFilesCache = new Map<string, { expiresAt: number; files: string[] }>();

function listWorkspaceSourceFiles(cwd: string, maxFiles = 380): string[] {
  const resolved = path.resolve(cwd);
  const now = Date.now();
  const cached = repoFilesCache.get(resolved);
  if (cached && cached.expiresAt > now) {
    return cached.files;
  }

  const ignored = new Set([
    ".git",
    "node_modules",
    "dist",
    "build",
    ".next",
    ".turbo",
    "__pycache__",
    ".venv",
    "venv",
    ".pytest_cache",
    "coverage",
    ".codegraph"
  ]);

  const collected: string[] = [];
  function walk(dir: string, depth: number) {
    if (depth > 5 || collected.length >= maxFiles) return;
    let entries: fs.Dirent[] = [];
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch {
      return;
    }
    for (const entry of entries) {
      if (collected.length >= maxFiles) break;
      if (ignored.has(entry.name) || entry.name.startsWith(".")) continue;
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        walk(full, depth + 1);
      } else if (/\.(ts|tsx|js|jsx|mjs|py|go|prisma|sql)$/i.test(entry.name)) {
        collected.push(path.relative(resolved, full).replace(/\\/g, "/"));
      }
    }
  }

  walk(resolved, 0);
  repoFilesCache.set(resolved, { expiresAt: now + 30_000, files: collected });
  return collected;
}

/**
 * Upward Blast-Radius / Caller Graph:
 * Scans workspace source files to identify which files import the modified files or reference
 * their touched symbols, distinguishing callers that were updated in the diff (`modifiedDependents`)
 * from untouched callers (`unmodifiedDependents` — potential breaking change candidates).
 */
export function extractReverseDependents(
  cwd: string,
  changedFiles: string[],
  structuralMap: FileStructuralSummary[] = []
): ReverseDependentsSummary {
  const resolvedCwd = path.resolve(cwd);
  const changedNorm = new Set(changedFiles.map((f) => f.replace(/\\/g, "/")));
  const targetStems = changedFiles
    .filter((f) => /\.(ts|tsx|js|jsx|mjs|py|go)$/i.test(f))
    .slice(0, 8)
    .map((f) => path.basename(f, path.extname(f)))
    .filter((stem) => stem && stem !== "index" && stem !== "__init__" && stem.length >= 3);

  const touchedSymbols = Array.from(
    new Set(
      structuralMap
        .flatMap((m) => m.touchedSymbols)
        .filter((s) => s.length >= 4 && !s.startsWith(".") && !s.startsWith("#"))
    )
  ).slice(0, 12);

  if (targetStems.length === 0 && touchedSymbols.length === 0) {
    return {
      modifiedDependents: [],
      unmodifiedDependents: [],
      referencedTouchedSymbols: {}
    };
  }

  const allSourceFiles = listWorkspaceSourceFiles(resolvedCwd);
  const modifiedDependents: string[] = [];
  const unmodifiedDependents: string[] = [];
  const referencedTouchedSymbols: Record<string, string[]> = {};

  for (const relFile of allSourceFiles) {
    if (modifiedDependents.length + unmodifiedDependents.length >= 16) break;
    const fullPath = path.join(resolvedCwd, relFile);
    try {
      const content = fs.readFileSync(fullPath, "utf8").slice(0, 12000);
      const importsChangedStem = targetStems.some(
        (stem) =>
          content.includes(`/${stem}`) ||
          content.includes(`.${stem}`) ||
          content.includes(`"${stem}"`) ||
          content.includes(`'${stem}'`)
      );

      if (importsChangedStem) {
        if (changedNorm.has(relFile)) {
          if (!modifiedDependents.includes(relFile)) modifiedDependents.push(relFile);
        } else if (!unmodifiedDependents.includes(relFile)) {
          unmodifiedDependents.push(relFile);
        }
      }

      if (!changedNorm.has(relFile)) {
        for (const sym of touchedSymbols) {
          if (content.includes(sym)) {
            referencedTouchedSymbols[sym] = referencedTouchedSymbols[sym] ?? [];
            if (referencedTouchedSymbols[sym].length < 5 && !referencedTouchedSymbols[sym].includes(relFile)) {
              referencedTouchedSymbols[sym].push(relFile);
            }
          }
        }
      }
    } catch {
      // ignore read errors
    }
  }

  return {
    modifiedDependents: modifiedDependents.slice(0, 10),
    unmodifiedDependents: unmodifiedDependents.slice(0, 10),
    referencedTouchedSymbols
  };
}

/**
 * Companion Test Suite Discovery:
 * Finds existing unit/integration test files (`*.test.ts`, `*.spec.ts`, `test_*.py`) on disk
 * corresponding to the modified files (even when those test files weren't edited in the diff!)
 * and extracts their test case titles so Jev knows what automated test coverage already exists.
 */
export function extractCompanionTestsContext(
  cwd: string,
  changedFiles: string[],
  maxTestFiles = 6
): Record<string, string[]> {
  const resolvedCwd = path.resolve(cwd);
  const allFiles = listWorkspaceSourceFiles(resolvedCwd);
  const testFilesInRepo = allFiles.filter(
    (f) =>
      /\.(test|spec)\.(ts|tsx|js|jsx|mjs)$/i.test(f) ||
      /(?:^|\/)test_[^/]+\.py$/i.test(f) ||
      /_test\.(py|go)$/i.test(f)
  );

  const stems = changedFiles
    .map((f) =>
      path
        .basename(f, path.extname(f))
        .replace(/\.(test|spec)$/i, "")
        .replace(/^test_/i, "")
    )
    .filter((s) => s.length >= 3);

  const matchedTestFiles: string[] = [];
  for (const tf of testFilesInRepo) {
    if (matchedTestFiles.length >= maxTestFiles) break;
    const tfLower = tf.toLowerCase();
    const directNameMatch =
      changedFiles.some((cf) => cf.replace(/\\/g, "/").toLowerCase() === tfLower) ||
      stems.some((stem) => tfLower.includes(stem.toLowerCase()));

    if (directNameMatch) {
      matchedTestFiles.push(tf);
      continue;
    }

    // Also check if the test file imports any of the changed file stems (e.g. policy-presets.test.ts importing policy-engine)
    try {
      const head = fs.readFileSync(path.join(resolvedCwd, tf), "utf8").slice(0, 2500);
      if (stems.some((stem) => head.includes(stem))) {
        matchedTestFiles.push(tf);
      }
    } catch {
      // ignore
    }
  }

  const testCasesByFile: Record<string, string[]> = {};
  const testCaseRegex =
    /(?:^\s*(?:test|it|describe)\(\s*["'`]([^"'`]+)["'`]|^\s*(?:async\s+)?def\s+(test_[A-Za-z0-9_]+))/gm;

  for (const relTest of matchedTestFiles) {
    try {
      const raw = fs.readFileSync(path.join(resolvedCwd, relTest), "utf8").slice(0, 15000);
      const cases: string[] = [];
      for (const m of raw.matchAll(testCaseRegex)) {
        const title = (m[1] ?? m[2] ?? "").trim();
        if (title && cases.length < 12 && !cases.includes(title)) {
          cases.push(title.slice(0, 110));
        }
      }
      if (cases.length > 0) {
        testCasesByFile[relTest] = cases;
      }
    } catch {
      // ignore
    }
  }

  return testCasesByFile;
}

/**
 * Domain Schema, Auth/Validation Convention & Environment Contract Fingerprint:
 * Extracts database/domain models (`schema.prisma`, `models.py`, `packages/contracts`),
 * `.env.example` variable names (never secret values!), and security/runtime conventions
 * (e.g., whether the workspace is an infrastructure/Proxmox CLI lab repo or a web app).
 */
export function extractDomainAndRuntimeFingerprint(cwd: string): string {
  const resolvedCwd = path.resolve(cwd);
  const parts: string[] = [];

  // 1. Check .env.example / .env.sample variable keys (only key names, never values)
  for (const envName of [".env.example", ".env.sample", "backend/.env.example"]) {
    const envPath = path.join(resolvedCwd, envName);
    if (fs.existsSync(envPath)) {
      try {
        const keys = fs
          .readFileSync(envPath, "utf8")
          .split(/\r?\n/)
          .map((l) => l.trim())
          .filter((l) => l && !l.startsWith("#") && l.includes("="))
          .map((l) => l.split("=")[0].trim())
          .filter(Boolean)
          .slice(0, 18);
        if (keys.length > 0) {
          parts.push(`env_contract_keys=[${keys.join(", ")}]`);
          break;
        }
      } catch {
        // ignore
      }
    }
  }

  // 2. Check Prisma / SQLAlchemy / Contracts domain models
  const prismaPath = [
    path.join(resolvedCwd, "prisma", "schema.prisma"),
    path.join(resolvedCwd, "packages", "db", "prisma", "schema.prisma"),
    path.join(resolvedCwd, "apps", "api", "prisma", "schema.prisma")
  ].find((p) => fs.existsSync(p));

  if (prismaPath) {
    try {
      const raw = fs.readFileSync(prismaPath, "utf8");
      const models = Array.from(raw.matchAll(/^model\s+([A-Za-z0-9_]+)\s*\{/gm), (m) => m[1]);
      if (models.length > 0) {
        parts.push(`prisma_models=[${models.slice(0, 20).join(", ")}]`);
      }
    } catch {
      // ignore
    }
  }

  // 3. Detect execution & security archetype (e.g., Proxmox/Lab CLI ops vs Web API vs Game Server)
  const allFiles = listWorkspaceSourceFiles(resolvedCwd, 200);
  const hasLabScripts = allFiles.some((f) => /^scripts\/lab\//i.test(f) || /proxmox/i.test(f));
  const hasContractsPkg = allFiles.some((f) => /^packages\/contracts\//i.test(f));
  const hasFastApi = allFiles.some((f) => /^backend\/app\//i.test(f));

  const archetypes: string[] = [];
  if (hasLabScripts) {
    archetypes.push(
      "authorized_infra_lab_automation (CLI/SSH/Proxmox scripts in scripts/lab/ are intended operator tools)"
    );
  }
  if (hasContractsPkg) {
    archetypes.push("shared_typesafe_monorepo_contracts (packages/contracts)");
  }
  if (hasFastApi) {
    archetypes.push("fastapi_pydantic_backend (backend/app)");
  }
  if (archetypes.length > 0) {
    parts.push(`archetypes=[${archetypes.join("; ")}]`);
  }

  return parts.join(" | ").slice(0, 900);
}

/**
 * Persists a learned Project Brain profile to `~/.mcp-jev/projects/<workspaceName>.json`
 * so Jev retains permanent architectural memory of each project across restarts.
 */
export function getProjectBrainFilePath(workspaceName: string): string {
  const safeName =
    (workspaceName || "workspace")
      .replace(/[^A-Za-z0-9_.-]/g, "_")
      .replace(/^\.+/, "_")
      .slice(0, 120) || "workspace";
  const brainDir = path.join(os.homedir(), ".mcp-jev", "projects");
  if (!fs.existsSync(brainDir)) {
    fs.mkdirSync(brainDir, { recursive: true });
  }
  const candidate = path.join(brainDir, `${safeName}.json`);
  if (!isWithinWorkspaceBoundary(brainDir, candidate)) {
    return path.join(brainDir, "workspace.json");
  }
  return candidate;
}

export function readLearnedHumanOverrides(workspaceName: string): LearnedHumanOverride[] {
  try {
    const brainPath = getProjectBrainFilePath(workspaceName);
    if (!fs.existsSync(brainPath)) return [];
    const parsed = JSON.parse(fs.readFileSync(brainPath, "utf8")) as {
      learnedHumanOverrides?: LearnedHumanOverride[];
    };
    return Array.isArray(parsed.learnedHumanOverrides) ? parsed.learnedHumanOverrides : [];
  } catch {
    return [];
  }
}

export function syncProjectBrainProfile(dna: ProjectDnaEnvelope): string | undefined {
  try {
    const brainPath = getProjectBrainFilePath(dna.workspaceName);
    const existingOverrides = readLearnedHumanOverrides(dna.workspaceName);
    const payload = {
      updatedAt: new Date().toISOString(),
      workspaceName: dna.workspaceName,
      workspacePath: dna.workspacePath,
      stackSummary: dna.stackSummary,
      repoTopology: dna.repoTopology,
      domainAndAuthFingerprint: dna.domainAndAuthFingerprint,
      projectRulesExcerpt: dna.projectRulesExcerpt?.slice(0, 1500),
      activeMemoryExcerpt: dna.activeMemoryExcerpt?.slice(0, 1000),
      learnedHumanOverrides:
        dna.learnedHumanOverrides && dna.learnedHumanOverrides.length > 0
          ? dna.learnedHumanOverrides
          : existingOverrides
    };
    fs.writeFileSync(brainPath, JSON.stringify(payload, null, 2), "utf8");
    return brainPath;
  } catch {
    return undefined;
  }
}

/**
 * Records a human feedback / override rule into the persistent Project Brain (`~/.mcp-jev/projects/<workspaceName>.json`)
 * so Jev immediately learns from user corrections and never repeats a false-positive BLOCK on that project.
 */
export function recordProjectFeedbackRule(input: {
  workspaceName: string;
  workspacePath?: string;
  tool?: string;
  feedbackType: "CORRECT" | "FALSE_POSITIVE_OVERRIDE" | "CUSTOM_RULE";
  rule: string;
  eventId?: string;
}): LearnedHumanOverride {
  const wsName = input.workspaceName || "workspace";
  if (input.workspacePath && fs.existsSync(input.workspacePath)) {
    buildProjectContextEnvelope(input.workspacePath);
  }
  const brainPath = getProjectBrainFilePath(wsName);
  let existingPayload: Record<string, unknown> = {
    updatedAt: new Date().toISOString(),
    workspaceName: wsName,
    workspacePath: input.workspacePath ?? wsName,
    stackSummary: "generic workspace",
    repoTopology: ""
  };
  if (fs.existsSync(brainPath)) {
    try {
      existingPayload = JSON.parse(fs.readFileSync(brainPath, "utf8")) as Record<string, unknown>;
    } catch {
      // ignore malformed JSON
    }
  }

  const overrides = Array.isArray(existingPayload.learnedHumanOverrides)
    ? (existingPayload.learnedHumanOverrides as LearnedHumanOverride[])
    : [];

  const newEntry: LearnedHumanOverride = {
    id: `rule_${Date.now()}_${crypto.randomBytes(4).toString("hex")}`,
    createdAt: new Date().toISOString(),
    tool: input.tool || "all_tools",
    feedbackType: input.feedbackType,
    rule: input.rule.trim().slice(0, 500),
    eventId: input.eventId
  };

  const updatedOverrides = [newEntry, ...overrides.filter((o) => o.rule !== newEntry.rule)].slice(
    0,
    25
  );
  existingPayload.updatedAt = new Date().toISOString();
  existingPayload.learnedHumanOverrides = updatedOverrides;
  fs.writeFileSync(brainPath, JSON.stringify(existingPayload, null, 2), "utf8");
  return newEntry;
}

export function removeProjectFeedbackRule(workspaceName: string, ruleId: string): boolean {
  try {
    const brainPath = getProjectBrainFilePath(workspaceName);
    if (!fs.existsSync(brainPath)) return false;
    const payload = JSON.parse(fs.readFileSync(brainPath, "utf8")) as Record<string, unknown>;
    const overrides = Array.isArray(payload.learnedHumanOverrides)
      ? (payload.learnedHumanOverrides as LearnedHumanOverride[])
      : [];
    payload.learnedHumanOverrides = overrides.filter((o) => o.id !== ruleId);
    payload.updatedAt = new Date().toISOString();
    fs.writeFileSync(brainPath, JSON.stringify(payload, null, 2), "utf8");
    return true;
  } catch {
    return false;
  }
}

export function listProjectBrainProfiles(): Array<Record<string, unknown>> {
  const brainDir = path.join(os.homedir(), ".mcp-jev", "projects");
  try {
    if (!fs.existsSync(brainDir)) {
      fs.mkdirSync(brainDir, { recursive: true });
    }
    // Ensure active workspaces from recent events have an up-to-date brain profile if they exist on disk
    const recentEvents = readSessionEvents(120);
    const seenWs = new Set<string>();
    for (const ev of recentEvents) {
      if (
        ev.workspacePath &&
        !seenWs.has(ev.workspacePath) &&
        !isGenericHostDirectory(ev.workspacePath) &&
        fs.existsSync(ev.workspacePath)
      ) {
        seenWs.add(ev.workspacePath);
        const targetJson = getProjectBrainFilePath(ev.workspace);
        if (!fs.existsSync(targetJson)) {
          buildProjectContextEnvelope(ev.workspacePath);
        }
      }
    }

    const files = fs.readdirSync(brainDir).filter((f) => f.endsWith(".json"));
    const profiles: Array<Record<string, unknown>> = [];
    for (const file of files) {
      try {
        const parsed = JSON.parse(fs.readFileSync(path.join(brainDir, file), "utf8")) as Record<
          string,
          unknown
        >;
        profiles.push(parsed);
      } catch {
        // ignore
      }
    }
    return profiles;
  } catch {
    return [];
  }
}

/**
 * Fast Pre-Flight Syntax & Compiler Probe:
 * Runs deterministic <700ms syntax checks (`python -m py_compile` for `.py`, `node --check` for `.js`/`.mjs`,
 * `JSON.parse` for `.json`) on modified files before sending the diff to Jev so Jev gets hard compiler ground truth.
 */
export function runFastSyntaxProbe(cwd: string, changedFiles: string[]): PreFlightSyntaxReport {
  const resolvedCwd = path.resolve(cwd);
  const checkedFiles: string[] = [];
  const errors: string[] = [];

  for (const rel of changedFiles.slice(0, 6)) {
    const fullPath = path.isAbsolute(rel) ? rel : path.join(resolvedCwd, rel);
    if (
      !isSafeReadableWorkspaceFile(resolvedCwd, fullPath) ||
      !fs.existsSync(fullPath) ||
      !fs.statSync(fullPath).isFile()
    ) {
      continue;
    }

    if (rel.endsWith(".json")) {
      checkedFiles.push(rel);
      try {
        JSON.parse(fs.readFileSync(fullPath, "utf8"));
      } catch (err) {
        errors.push(`${rel}: JSON syntax error (${err instanceof Error ? err.message : "invalid"})`);
      }
    } else if (/\.(js|mjs|cjs)$/i.test(rel)) {
      checkedFiles.push(rel);
      try {
        execFileSync(process.execPath, ["--check", fullPath], {
          cwd: resolvedCwd,
          encoding: "utf8",
          timeout: 700,
          stdio: ["ignore", "pipe", "pipe"]
        });
      } catch (err) {
        const stderr =
          err && typeof err === "object" && "stderr" in err ? String(err.stderr) : "SyntaxError";
        errors.push(`${rel}: ${stderr.trim().slice(0, 240)}`);
      }
    } else if (/\.py$/i.test(rel)) {
      checkedFiles.push(rel);
      try {
        execFileSync(resolvePythonExecutable(), ["-m", "py_compile", fullPath], {
          cwd: resolvedCwd,
          encoding: "utf8",
          timeout: 800,
          stdio: ["ignore", "pipe", "pipe"]
        });
      } catch (err) {
        const stderr =
          err && typeof err === "object" && "stderr" in err ? String(err.stderr) : "";
        if (stderr.includes("SyntaxError") || stderr.includes("IndentationError")) {
          errors.push(`${rel}: ${stderr.trim().slice(0, 240)}`);
        }
      }
    }
  }

  if (checkedFiles.length === 0) {
    return { status: "SKIPPED", checkedFiles: [], errors: [] };
  }
  return {
    status: errors.length > 0 ? "SYNTAX_ERROR" : "PASS",
    checkedFiles,
    errors
  };
}
