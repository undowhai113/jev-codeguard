#!/usr/bin/env node
import fs from "node:fs";
import { startStdioServer, McpJevDispatcher } from "../mcp/server.js";
import { runPreToolHook } from "./hook-runner.js";
import { runSetup } from "./setup.js";
import { startDashboardServer } from "../dashboard/server.js";

function readStdin(): Promise<string> {
  return new Promise((resolve) => {
    if (process.stdin.isTTY) {
      resolve("");
      return;
    }
    let data = "";
    process.stdin.setEncoding("utf8");
    process.stdin.on("data", (chunk) => {
      data += chunk;
    });
    process.stdin.on("end", () => resolve(data));
    process.stdin.on("error", () => resolve(data));
  });
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
    const { url } = await startDashboardServer({ port });
    console.log(`[mcp-jev radar]: Live Agent Q&A Portal listening at ${url}`);
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
    const question = getArgValue(args, "--question") ?? args[1] ?? "";
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
    const filePath = getArgValue(args, "--file") ?? args[1];
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
    const spec = getArgValue(args, "--spec") ?? args[1] ?? "Verify git diff quality and safety";
    const dispatcher = new McpJevDispatcher();
    const res = await dispatcher.verifyDiff({ spec, agent: explicitAgent });
    process.stdout.write(`${JSON.stringify(res, null, 2)}\n`);
    process.exit(res.decision.verdict === "BLOCK" ? 2 : 0);
  }

  if (subcommand === "setup" || subcommand === "init") {
    const apiKey = getArgValue(args, "--api-key");
    const report = runSetup({ apiKey });
    console.log("=== MCP-Jev Setup Complete ===");
    if (report.configSavedPath) {
      console.log(`[+] Saved API key config to: ${report.configSavedPath}`);
    }
    if (report.skillInstalledPath) {
      console.log(`[+] Installed companion skill to: ${report.skillInstalledPath}`);
    }
    console.log("\n--- 1. Add to MCP Settings (Antigravity / Claude Code / Cursor / Windsurf) ---");
    console.log(report.mcpConfigSnippet);
    console.log("\n--- 2. OpenAI Codex CLI (~/.codex/config.toml) ---");
    console.log(report.codexTomlSnippet);
    console.log("\n--- 3. Optional Zero-Trust PreToolUse Hook (.claude/settings.json) ---");
    console.log(report.claudeHookSnippet);
    return;
  }

  console.log(`mcp-jev v1.1.0 — System-1 Decision Engine, Skill Auditor & Live Radar Portal

Usage:
  mcp-jev serve                                                        Start MCP stdio server + auto-start Radar Portal (default)
  mcp-jev dashboard [--port 4399]                                      Launch standalone Live Radar Portal (http://localhost:4399)
  mcp-jev setup [--api-key <key>]                                      Save API key (0600), install SKILL.md, and print IDE configs
  mcp-jev autopilot --question "<q>" --opt A="desc" --opt B="desc"     Run Human-Proxy Autopilot (auto-proceeds only with JEV_AUTOPILOT=1)
  mcp-jev gate [--command "<cmd>" | --file <path>]                     Run Zero-Trust PreToolUse Hook Firewall (stdin or flags)
  mcp-jev audit [--file <path>]                                        Run Skill-Backed Security & Quality Audit on file or git diff
  mcp-jev verify-diff --spec "<spec>"                                  Run Zero-Token Local Git Diff Verification Gate
`);
}

main().catch((err) => {
  console.error("[mcp-jev fatal]:", err instanceof Error ? err.message : String(err));
  process.exit(1);
});
