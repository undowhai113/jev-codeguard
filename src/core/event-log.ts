import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import crypto from "node:crypto";

export type AgentIdentity = "Codex" | "Gemini" | "Claude" | "Cursor" | "CLI";

export type EventVerdict =
  | "AUTOPILOT_PROCEED"
  | "ASK_HUMAN"
  | "ALLOW"
  | "ASK_USER"
  | "BLOCK"
  | "INFO";

export interface JevSessionEvent {
  id: string;
  timestamp: string;
  agent: AgentIdentity;
  workspace: string;
  workspacePath?: string;
  tool: string;
  questionOrTitle: string;
  optionsOrInput: Record<string, string>;
  verdict: EventVerdict;
  selectedOption: string;
  selectedProbability: number;
  probabilities: Record<string, number>;
  directive: string;
  latencyMs: number;
  costUsd: number;
  cached: boolean;
}

export function getEventsFilePath(): string {
  if (process.env.JEV_EVENTS_FILE) {
    return process.env.JEV_EVENTS_FILE;
  }
  return path.join(os.homedir(), ".mcp-jev", "events.jsonl");
}

/** events.jsonl -> events.1.jsonl (the single rotated generation). */
export function getRotatedEventsFilePath(filePath: string = getEventsFilePath()): string {
  const ext = path.extname(filePath);
  const stem = ext ? filePath.slice(0, -ext.length) : filePath;
  return `${stem}.1${ext || ".jsonl"}`;
}

const DEFAULT_MAX_EVENTS_FILE_BYTES = 5 * 1024 * 1024;
const MIN_MAX_EVENTS_FILE_BYTES = 4 * 1024;
const MAX_MAX_EVENTS_FILE_BYTES = 512 * 1024 * 1024;
const ROTATE_LOCK_STALE_MS = 30_000;
const TAIL_CHUNK_BYTES = 64 * 1024;
const TAIL_MAX_SCAN_BYTES = 16 * 1024 * 1024;

/** Rotation threshold; override with JEV_EVENTS_MAX_BYTES (bounded to 4 KiB..512 MiB). */
export function getMaxEventsFileBytes(): number {
  const raw = Number.parseInt(process.env.JEV_EVENTS_MAX_BYTES ?? "", 10);
  if (!Number.isFinite(raw)) return DEFAULT_MAX_EVENTS_FILE_BYTES;
  return Math.min(MAX_MAX_EVENTS_FILE_BYTES, Math.max(MIN_MAX_EVENTS_FILE_BYTES, raw));
}

/**
 * Rotates events.jsonl to events.1.jsonl once it reaches maxBytes. Codex and
 * Antigravity run separate MCP processes against the same file, so rotation takes an
 * exclusive lock file and re-checks the size under the lock; a process that loses the
 * race simply skips rotation. Appends never rewrite existing lines.
 */
function rotateEventsFileIfNeeded(filePath: string, maxBytes: number): void {
  let size: number;
  try {
    size = fs.statSync(filePath).size;
  } catch {
    return; // nothing to rotate yet
  }
  if (size < maxBytes) return;

  const lockPath = `${filePath}.rotate.lock`;
  let lockFd: number;
  try {
    lockFd = fs.openSync(lockPath, "wx");
  } catch {
    try {
      if (Date.now() - fs.statSync(lockPath).mtimeMs > ROTATE_LOCK_STALE_MS) {
        fs.unlinkSync(lockPath); // left behind by a crashed process; retry next append
      }
    } catch {
      // lock vanished or is unreadable; another process owns rotation
    }
    return;
  }
  try {
    if (fs.statSync(filePath).size >= maxBytes) {
      fs.renameSync(filePath, getRotatedEventsFilePath(filePath));
    }
  } catch {
    // e.g. EPERM/EBUSY on Windows while a reader holds events.1.jsonl; retry later
  } finally {
    fs.closeSync(lockFd);
    try {
      fs.unlinkSync(lockPath);
    } catch {
      // ignore
    }
  }
}

/**
 * Returns up to maxLines complete, non-empty lines from the end of a file (oldest
 * first) without reading the whole file.
 */
function readTailLines(filePath: string, maxLines: number): string[] {
  if (maxLines <= 0) return [];
  let fd: number;
  try {
    fd = fs.openSync(filePath, "r");
  } catch {
    return [];
  }
  try {
    const size = fs.fstatSync(fd).size;
    let position = size;
    let newlines = 0;
    const chunks: Buffer[] = [];
    while (position > 0 && newlines <= maxLines && size - position < TAIL_MAX_SCAN_BYTES) {
      const readSize = Math.min(TAIL_CHUNK_BYTES, position);
      position -= readSize;
      const chunk = Buffer.alloc(readSize);
      fs.readSync(fd, chunk, 0, readSize, position);
      for (const byte of chunk) {
        if (byte === 0x0a) newlines += 1;
      }
      chunks.unshift(chunk);
    }
    const lines = Buffer.concat(chunks).toString("utf8").split(/\r?\n/);
    if (position > 0) {
      lines.shift(); // first line may be partial (and may hold a split UTF-8 sequence)
    }
    return lines.filter((line) => line.trim().length > 0).slice(-maxLines);
  } catch {
    return [];
  } finally {
    fs.closeSync(fd);
  }
}

function parseEventLines(lines: string[]): JevSessionEvent[] {
  const parsed: JevSessionEvent[] = [];
  for (const line of lines) {
    try {
      parsed.push(JSON.parse(line) as JevSessionEvent);
    } catch {
      // Ignore malformed line
    }
  }
  return parsed;
}

export function detectAgentIdentity(explicitAgent?: string): AgentIdentity {
  const raw = (explicitAgent ?? process.env.JEV_AGENT_NAME ?? "").trim().toLowerCase();
  if (raw.includes("codex") || raw.includes("openai")) {
    return "Codex";
  }
  if (raw.includes("claude") || raw.includes("anthropic")) {
    return "Claude";
  }
  if (raw.includes("cursor")) {
    return "Cursor";
  }
  if (raw.includes("gemini") || raw.includes("antigravity") || raw.includes("google")) {
    return "Gemini";
  }
  if (raw.includes("cli")) {
    return "CLI";
  }

  // Auto-detect OpenAI Codex environment variables
  if (
    process.env.CODEX_HOME ||
    process.env.CODEX_CLI_PATH ||
    process.env.CODEX_SANDBOX ||
    process.env.CODEX_WINDOWS_REGISTERED_CORE ||
    process.env.OPENAI_CODEX
  ) {
    return "Codex";
  }

  // Auto-detect Claude Code environment variables
  if (process.env.CLAUDECODE || process.env.CLAUDE_CODE_ENTRYPOINT) {
    return "Claude";
  }

  // Auto-detect Cursor environment variables
  if (process.env.CURSOR_TRACE_ID || process.env.CURSOR_AGENT) {
    return "Cursor";
  }

  // Auto-detect Antigravity / Gemini environment variables
  if (
    process.env.ANTIGRAVITY_CLI_ALIAS ||
    process.env.ANTIGRAVITY_AGENT ||
    process.env.GEMINI_CLI
  ) {
    return "Gemini";
  }

  // If running as MCP stdio server (`serve` or default no-arg), default to Gemini/Antigravity host
  const sub = process.argv[2];
  if (!sub || sub === "serve" || sub === "mcp") {
    return "Gemini";
  }

  return "CLI";
}

export function detectWorkspaceName(workingDir?: string): string {
  const target = workingDir || process.cwd();
  const base = path.basename(path.resolve(target));
  return base || "workspace";
}

export function recordSessionEvent(
  input: Omit<JevSessionEvent, "id" | "timestamp" | "agent" | "workspace"> & {
    agent?: AgentIdentity | string;
    workspace?: string;
    workingDirectory?: string;
  }
): JevSessionEvent {
  const resolvedPath = path.resolve(input.workingDirectory || process.cwd());
  const event: JevSessionEvent = {
    id: `jev_${Date.now()}_${crypto.randomBytes(3).toString("hex")}`,
    timestamp: new Date().toISOString(),
    agent: detectAgentIdentity(input.agent),
    workspace: input.workspace || detectWorkspaceName(input.workingDirectory),
    workspacePath: resolvedPath,
    tool: input.tool,
    questionOrTitle: input.questionOrTitle,
    optionsOrInput: input.optionsOrInput,
    verdict: input.verdict,
    selectedOption: input.selectedOption,
    selectedProbability: input.selectedProbability,
    probabilities: input.probabilities,
    directive: input.directive,
    latencyMs: input.latencyMs,
    costUsd: input.costUsd,
    cached: input.cached
  };

  try {
    const filePath = getEventsFilePath();
    fs.mkdirSync(path.dirname(filePath), { recursive: true });
    rotateEventsFileIfNeeded(filePath, getMaxEventsFileBytes());
    // One append per event (O_APPEND): concurrent writers from other agent processes
    // cannot overwrite each other's lines, unlike the old read-trim-rewrite cycle.
    fs.appendFileSync(filePath, `${JSON.stringify(event)}\n`, "utf8");
  } catch {
    // Non-fatal if filesystem is read-only
  }

  return event;
}

/** Newest-first events from events.jsonl, topped up from events.1.jsonl after a rotation. */
export function readSessionEvents(limit = 100): JevSessionEvent[] {
  const boundedLimit = Math.max(0, Math.floor(limit));
  if (boundedLimit === 0) return [];
  try {
    const filePath = getEventsFilePath();
    const current = parseEventLines(readTailLines(filePath, boundedLimit));
    let combined = current;
    if (current.length < boundedLimit) {
      const rotated = parseEventLines(
        readTailLines(getRotatedEventsFilePath(filePath), boundedLimit - current.length)
      );
      combined = [...rotated, ...current];
    }
    return combined.reverse().slice(0, boundedLimit);
  } catch {
    return [];
  }
}

export function clearSessionEvents(): void {
  const filePath = getEventsFilePath();
  try {
    if (fs.existsSync(filePath)) {
      fs.writeFileSync(filePath, "", "utf8");
    }
  } catch {
    // Ignore
  }
  try {
    fs.rmSync(getRotatedEventsFilePath(filePath), { force: true });
  } catch {
    // Ignore
  }
}
