import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

export interface RuntimeConfig {
  apiKey?: string;
  autopilot?: boolean;
  updatedAt?: string;
}

export type AutopilotConfigSource = "env" | "config" | "default";

export interface AutopilotRuntimeStatus {
  enabled: boolean;
  source: AutopilotConfigSource;
  envLocked: boolean;
  configPath?: string;
  guardLockWindowMin: number;
}

/**
 * Resolves the runtime config file path (`~/.mcp-jev/config.json` by default).
 *
 * Honors `JEV_CONFIG_PATH`, then `HOME`/`USERPROFILE` from the supplied `env`,
 * falling back to `os.homedir()` only when `env === process.env`. Passing an
 * isolated synthetic env (e.g. `{}` in tests) returns `undefined` so tests never
 * accidentally depend on the host user's `~/.mcp-jev/config.json`.
 */
export function getRuntimeConfigPath(
  env: NodeJS.ProcessEnv = process.env
): string | undefined {
  const explicit = env.JEV_CONFIG_PATH?.trim();
  if (explicit) {
    return path.resolve(explicit);
  }
  const envHome = (
    process.platform === "win32"
      ? env.USERPROFILE || env.HOME
      : env.HOME || env.USERPROFILE
  )?.trim();
  if (envHome) {
    return path.join(envHome, ".mcp-jev", "config.json");
  }
  if (env === process.env) {
    return path.join(os.homedir(), ".mcp-jev", "config.json");
  }
  return undefined;
}

function parseRuntimeConfigText(rawText: string): RuntimeConfig {
  const parsed = JSON.parse(rawText) as unknown;
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new Error("Runtime config must be a JSON object");
  }
  const raw = parsed as Record<string, unknown>;
  const out: RuntimeConfig = {};
  if (typeof raw.apiKey === "string" && raw.apiKey.trim().length > 0) {
    out.apiKey = raw.apiKey.trim();
  }
  if (typeof raw.autopilot === "boolean") {
    out.autopilot = raw.autopilot;
  }
  if (typeof raw.updatedAt === "string") {
    out.updatedAt = raw.updatedAt;
  }
  return out;
}

export function readRuntimeConfig(env: NodeJS.ProcessEnv = process.env): RuntimeConfig {
  const configPath = getRuntimeConfigPath(env);
  if (!configPath || !fs.existsSync(configPath)) {
    return {};
  }
  try {
    return parseRuntimeConfigText(fs.readFileSync(configPath, "utf8"));
  } catch {
    return {};
  }
}

/**
 * Atomically merges updates into `~/.mcp-jev/config.json` while preserving all
 * untouched fields (`apiKey`, `autopilot`). Fails fast if `env` resolves no config
 * path or if an existing config file cannot be parsed (preventing accidental
 * clobbering of saved credentials). Enforces `0700` dir and `0600` file permissions.
 */
export function updateRuntimeConfig(
  patch: { apiKey?: string; autopilot?: boolean },
  env: NodeJS.ProcessEnv = process.env
): { configPath: string; config: RuntimeConfig } {
  const configPath = getRuntimeConfigPath(env);
  if (!configPath) {
    throw new Error(
      "Cannot resolve runtime config path from provided environment (set JEV_CONFIG_PATH or HOME/USERPROFILE)."
    );
  }

  let existing: RuntimeConfig = {};
  if (fs.existsSync(configPath)) {
    // Strictly parse existing file so transient corruption never silently drops apiKey
    existing = parseRuntimeConfigText(fs.readFileSync(configPath, "utf8"));
  }

  const next: RuntimeConfig = {
    ...existing,
    ...(patch.apiKey !== undefined ? { apiKey: patch.apiKey.trim() } : {}),
    ...(patch.autopilot !== undefined ? { autopilot: patch.autopilot } : {}),
    updatedAt: new Date().toISOString()
  };

  const dir = path.dirname(configPath);
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  try {
    fs.chmodSync(dir, 0o700);
  } catch {
    // chmod may be a no-op on Windows NTFS
  }

  const tmpPath = path.join(
    dir,
    `.config.${process.pid}.${crypto.randomBytes(6).toString("hex")}.tmp`
  );
  try {
    fs.writeFileSync(tmpPath, JSON.stringify(next, null, 2), {
      encoding: "utf8",
      mode: 0o600
    });
    try {
      fs.chmodSync(tmpPath, 0o600);
    } catch {
      // ignore on Windows NTFS
    }
    fs.renameSync(tmpPath, configPath);
  } catch (err) {
    try {
      if (fs.existsSync(tmpPath)) fs.unlinkSync(tmpPath);
    } catch {
      // ignore cleanup error
    }
    throw err;
  }

  return { configPath, config: next };
}

/**
 * Resolves the effective Autopilot state and its source:
 * 1. Explicit `JEV_AUTOPILOT` env var (`1`/`true` or `0`/`false`) — highest precedence (envLocked=true).
 * 2. Persistent `autopilot` boolean in `~/.mcp-jev/config.json` (toggled via CLI or Live Radar `:4399`).
 * 3. Safe default: `false` (`ASK_HUMAN`).
 */
export function getAutopilotRuntimeStatus(
  env: NodeJS.ProcessEnv = process.env,
  guardLockWindowMin = 15
): AutopilotRuntimeStatus {
  const configPath = getRuntimeConfigPath(env);
  const rawEnv = (env.JEV_AUTOPILOT ?? "").trim().toLowerCase();
  if (rawEnv === "1" || rawEnv === "true") {
    return {
      enabled: true,
      source: "env",
      envLocked: true,
      configPath,
      guardLockWindowMin
    };
  }
  if (rawEnv === "0" || rawEnv === "false") {
    return {
      enabled: false,
      source: "env",
      envLocked: true,
      configPath,
      guardLockWindowMin
    };
  }

  const saved = readRuntimeConfig(env);
  if (typeof saved.autopilot === "boolean") {
    return {
      enabled: saved.autopilot,
      source: "config",
      envLocked: false,
      configPath,
      guardLockWindowMin
    };
  }

  return {
    enabled: false,
    source: "default",
    envLocked: false,
    configPath,
    guardLockWindowMin
  };
}
