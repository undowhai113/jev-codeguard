#!/usr/bin/env node
import fs from "node:fs";
import { startStdioServer, McpJevDispatcher } from "../mcp/server.js";
import { runPreToolHook } from "./hook-runner.js";
import { runSetup } from "./setup.js";
import { startDashboardServer } from "../dashboard/server.js";
import { getAutopilotRuntimeStatus, updateRuntimeConfig } from "../core/runtime-config.js";

const MAX_STDIN_BYTES = 2 * 1024 * 1024;

function readStdin(maxBytes = MAX_STDIN_BYTES): Promise<string> {
  return new Promise((resolve) => {
    if (process.stdin.isTTY) {
      resolve("");
      return;
    }
    const chunks: Buffer[] = [];
    let total = 0;
    let settled = false;
    const finish = () => {
      if (settled) return;
      settled = true;
      resolve(Buffer.concat(chunks).toString("utf8"));
    };
    process.stdin.on("data", (chunk: Buffer | string) => {
      const buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk, "utf8");
      if (total < maxBytes) {
        const remaining = maxBytes - total;
        chunks.push(buf.length <= remaining ? buf : buf.subarray(0, remaining));
        total += Math.min(buf.length, remaining);
      }
    });
    process.stdin.on("end", finish);
    process.stdin.on("error", finish);
  });
}

function firstPositionalArg(args: string[]): string | undefined {
  const candidate = args[1];
  if (!candidate || candidate.startsWith("-")) {
    return undefined;
  }
  return candidate;
}

function getArgValue(args: string[], flag: string): string | undefined {
  const idx = args.indexOf(flag);
  if (idx !== -1 && idx + 1 < args.length) {
    return args[idx + 1];
  }
  return undefined;
}

function getAllArgValues(args: string[], flag: string): string[] {
  const values: string[] = [];
  for (let i = 0; i < args.length - 1; i++) {
    if (args[i] === flag) {
      values.push(args[i + 1]);
    }
  }
  return values;
}

async function main(): Promise<void> {
  const args = process.argv.slice(2);
  const binName = process.argv[1] ?? "";
  const isGateBinary = binName.endsWith("jev-gate");
  const subcommand = args[0] ?? (isGateBinary ? "gate" : "serve");

  if (subcommand === "serve" || subcommand === "mcp") {
    // Automatically ensure the Live Radar Portal is running on port 4399 (ignores EADDRINUSE if already active)
    startDashboardServer({ port: 4399 }).catch(() => {});
    await startStdioServer();
    return;
  }

  if (subcommand === "dashboard" || subcommand === "portal" || subcommand === "radar") {
    const portArg = getArgValue(args, "--port");
    const port = portArg ? Number(portArg) : 4399;
    if (!Number.isInteger(port) || port < 1 || port > 65535) {
      console.error("[jev-codeguard radar]: --port must be an integer between 1 and 65535");
      process.exit(1);
    }
    const { url } = await startDashboardServer({ port });
    console.log(`[jev-codeguard radar]: Live Agent Q&A Portal listening at ${url}`);
    return;
  }

  const explicitAgent = getArgValue(args, "--agent");

  if (subcommand === "gate" || subcommand === "pre-tool") {
    const cmdArg = getArgValue(args, "--command");
    const fileArg = getArgValue(args, "--file");
    let rawPayload = "";

    if (cmdArg) {
      rawPayload = JSON.stringify({ command: cmdArg });
    } else if (fileArg && fs.existsSync(fileArg)) {
      rawPayload = JSON.stringify({
        file_path: fileArg,
        code: fs.readFileSync(fileArg, "utf8")
      });
    } else {
      rawPayload = await readStdin();
    }

    const result = await runPreToolHook(rawPayload);
    if (result.stdout) {
      process.stdout.write(`${result.stdout}\n`);
    }
    if (result.stderr) {
      process.stderr.write(`${result.stderr}\n`);
    }
    process.exit(result.exitCode);
  }

  if (subcommand === "autopilot" || subcommand === "decide") {
    const question = getArgValue(args, "--question") ?? firstPositionalArg(args) ?? "";
    const context = getArgValue(args, "--context") ?? "";
    const optFlags = getAllArgValues(args, "--opt");
    const optionsRaw = getArgValue(args, "--options");

    const options: Record<string, string> = {};
    for (const entry of optFlags) {
      const eqIdx = entry.indexOf("=");
      if (eqIdx > 0) {
        const key = entry.slice(0, eqIdx).trim();
        const val = entry.slice(eqIdx + 1).trim();
        if (key) options[key] = val;
      }
    }

    if (Object.keys(options).length === 0 && optionsRaw) {
      try {
        Object.assign(options, JSON.parse(optionsRaw) as Record<string, string>);
      } catch {
        console.error("[mcp-jev autopilot]: Pass --opt key=\"description\" (2+ times) or valid --options JSON");
        process.exit(1);
      }
    }

    if (Object.keys(options).length < 2) {
      console.error("[mcp-jev autopilot]: Provide at least 2 options via --opt key=\"description\"");
      process.exit(1);
    }

    const dispatcher = new McpJevDispatcher();
    const res = await dispatcher.autopilotDecide({
      question,
      options,
      context,
      agent: explicitAgent
    });
    process.stdout.write(`${JSON.stringify(res, null, 2)}\n`);
    process.exit(0);
  }

  if (subcommand === "audit") {
    const filePath = getArgValue(args, "--file") ?? firstPositionalArg(args);
    const code =
      filePath && fs.existsSync(filePath) ? fs.readFileSync(filePath, "utf8") : undefined;
    const dispatcher = new McpJevDispatcher();
    const res = await dispatcher.auditCode({
      code,
      file_path: filePath,
      agent: explicitAgent
    });
    process.stdout.write(`${JSON.stringify(res, null, 2)}\n`);
    process.exit(res.verdict === "BLOCK" ? 2 : 0);
  }

  if (subcommand === "verify-diff") {
    const spec =
      getArgValue(args, "--spec") ??
      firstPositionalArg(args) ??
      "Verify git diff quality and safety";
    const dispatcher = new McpJevDispatcher();
    const res = await dispatcher.verifyDiff({ spec, agent: explicitAgent });
    process.stdout.write(`${JSON.stringify(res, null, 2)}\n`);
    process.exit(res.decision.verdict === "BLOCK" ? 2 : 0);
  }

  if (subcommand === "autopilot-mode") {
    const action = (firstPositionalArg(args) ?? "status").toLowerCase();
    if (action === "on" || action === "enable" || action === "true") {
      const saved = updateRuntimeConfig({ autopilot: true });
      const status = getAutopilotRuntimeStatus();
      console.log(
        `[jev-codeguard autopilot]: Saved autopilot=true to ${saved.configPath} (effective=${status.enabled}, source=${status.source}).`
      );
      if (status.envLocked) {
        console.log(
          `[!] Note: JEV_AUTOPILOT=${process.env.JEV_AUTOPILOT} in your environment overrides config.json.`
        );
      }
      return;
    }
    if (action === "off" || action === "disable" || action === "false") {
      const saved = updateRuntimeConfig({ autopilot: false });
      const status = getAutopilotRuntimeStatus();
      console.log(
        `[jev-codeguard autopilot]: Saved autopilot=false to ${saved.configPath} (effective=${status.enabled}, source=${status.source}).`
      );
      if (status.envLocked) {
        console.log(
          `[!] Note: JEV_AUTOPILOT=${process.env.JEV_AUTOPILOT} in your environment overrides config.json.`
        );
      }
      return;
    }
    if (action === "status") {
      const status = getAutopilotRuntimeStatus();
      console.log(JSON.stringify(status, null, 2));
      return;
    }
    console.error(
      `[jev-codeguard autopilot]: Unknown action "${action}". Expected one of: on, off, status.`
    );
    process.exit(1);
  }

  if (subcommand === "setup" || subcommand === "init") {
    const apiKey = getArgValue(args, "--api-key");
    const portable = args.includes("--portable") ? true : undefined;
    const autopilot = args.includes("--autopilot")
      ? true
      : args.includes("--no-autopilot")
        ? false
        : undefined;
    const report = runSetup({ apiKey, portable, autopilot });
    console.log("=== Jev CodeGuard Setup Complete ===");
    if (report.configSavedPath) {
      console.log(`[+] Saved runtime config to: ${report.configSavedPath}`);
    }
    console.log(
      `[+] Human-Proxy Autopilot Mode: ${report.autopilotEnabled ? "ENABLED (auto-decides reversible tech choices; 15m guard lock active)" : "OFF (safe default — pass --autopilot or toggle on Live Radar :4399)"}`
    );
    if (report.installedSkillPaths.length > 0) {
      for (const p of report.installedSkillPaths) {
        console.log(`[+] Installed companion skill to: ${p}`);
      }
    }
    console.log("\n--- 1. Add to MCP Settings (Antigravity / Claude Code / Cursor / Windsurf) ---");
    console.log(report.mcpConfigSnippet);
    console.log("\n--- 2. OpenAI Codex CLI (~/.codex/config.toml) ---");
    console.log(report.codexTomlSnippet);
    console.log("\n--- 3. Optional Zero-Trust PreToolUse Hook (.claude/settings.json) ---");
    console.log(report.claudeHookSnippet);
    console.log("\n--- 4. Agent Instructions (CLAUDE.md / .cursorrules / AGENTS.md) ---");
    console.log(report.agentRulesSnippet);
    return;
  }

  console.log(`jev-codeguard v1.2.0 — System-1 Decision Engine, Skill Auditor & Live Radar Portal

Usage:
  jev-codeguard serve                                                        Start MCP stdio server + auto-start Radar Portal (default)
  jev-codeguard dashboard [--port 4399]                                      Launch standalone Live Radar Portal (http://localhost:4399)
  jev-codeguard setup [--api-key <key>] [--autopilot] [--portable]           Save config (0600), install SKILL.md, and print IDE configs
  jev-codeguard autopilot-mode [on|off|status]                               Toggle persistent Human-Proxy Autopilot across all agents
  jev-codeguard autopilot --question "<q>" --opt A="desc" --opt B="desc"     Run Human-Proxy Autopilot (reversible tech choices)
  jev-codeguard gate [--command "<cmd>" | --file <path>]                     Run Zero-Trust PreToolUse Hook Firewall (stdin or flags)
  jev-codeguard audit [--file <path>]                                        Run Skill-Backed Security & Quality Audit on file or git diff
  jev-codeguard verify-diff --spec "<spec>"                                  Run Zero-Token Local Git Diff Verification Gate
`);
}

main().catch((err) => {
  console.error("[mcp-jev fatal]:", err instanceof Error ? err.message : String(err));
  process.exit(1);
});
