import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { z } from "zod";
import { getAutopilotRuntimeStatus, updateRuntimeConfig } from "../core/runtime-config.js";

const SetupOptionsSchema = z.object({
  apiKey: z
    .string()
    .trim()
    .min(8, "API key must be at least 8 characters")
    .max(256, "API key exceeds maximum length")
    .regex(/^[A-Za-z0-9_.-]+$/, "API key contains invalid characters")
    .optional(),
  autopilot: z.boolean().optional(),
  installSkill: z.boolean().optional(),
  skillsTargetDir: z
    .string()
    .trim()
    .min(1)
    .max(512)
    .refine((p) => !p.includes("\u0000"), "Invalid path")
    .optional(),
  portable: z.boolean().optional(),
  skipAutoRegister: z.boolean().optional(),
  antigravityMcpConfigPath: z
    .string()
    .trim()
    .min(1)
    .max(512)
    .refine((p) => !p.includes("\u0000"), "Invalid path")
    .optional(),
  projectRootOverride: z.string().trim().min(1).max(512).optional()
});

export interface SetupOptions {
  apiKey?: string;
  autopilot?: boolean;
  installSkill?: boolean;
  skillsTargetDir?: string;
  portable?: boolean;
  skipAutoRegister?: boolean;
  antigravityMcpConfigPath?: string;
  projectRootOverride?: string;
}

export interface SetupReport {
  configSavedPath?: string;
  autopilotEnabled: boolean;
  skillInstalledPath?: string;
  installedSkillPaths: string[];
  mcpEntrypoint: string;
  portableMode: boolean;
  mcpConfigSnippet: string;
  codexTomlSnippet: string;
  claudeHookSnippet: string;
  agentRulesSnippet: string;
}

export function isPackagedInstallRoot(rootDir: string): boolean {
  const normalized = rootDir.replace(/\\/g, "/");
  return /\/_npx\/|\/node_modules\//i.test(normalized);
}

export function buildAgentRulesSnippet(autopilotEnabled: boolean): string {
  return [
    "## Jev CodeGuard (`mcp-jev`) Directives",
    "- Before running destructive or external shell commands, call `jev_guard_action` with the verbatim command in `exact_command`.",
    autopilotEnabled
      ? "- Before interrupting the user on reversible technical choices (library, folder layout, test seam, implementation trade-off), call `jev_autopilot_decide` first: if `mode === \"AUTOPILOT_PROCEED\"`, proceed with `selectedOption` and mention your choice in one line; only ask the user when `mode === \"ASK_HUMAN\"`."
      : "- When weighing multiple technical options, you may call `jev_autopilot_decide` for a calibrated recommendation (enable hands-free auto-decisions anytime via `jev-codeguard autopilot-mode on` or the Live Radar toggle on `http://127.0.0.1:4399`).",
    "- Never use `jev_autopilot_decide` to bypass a `jev_guard_action` `ASK_USER`/`BLOCK` verdict (hard-locked for 15 minutes).",
    "- After writing security-sensitive or animation code, run `jev_audit_code`, and run `jev_verify_diff` before declaring completion."
  ].join("\n");
}

export function runSetup(rawOptions: SetupOptions = {}): SetupReport {
  const options = SetupOptionsSchema.parse({
    ...rawOptions,
    apiKey: rawOptions.apiKey && rawOptions.apiKey.trim().length > 0 ? rawOptions.apiKey : undefined
  });
  const homeDir = os.homedir();
  let configSavedPath: string | undefined;

  if (options.apiKey !== undefined || options.autopilot !== undefined) {
    const saved = updateRuntimeConfig({
      ...(options.apiKey !== undefined ? { apiKey: options.apiKey } : {}),
      ...(options.autopilot !== undefined ? { autopilot: options.autopilot } : {})
    });
    configSavedPath = saved.configPath;
  }

  const autopilotEnabled =
    options.autopilot ?? getAutopilotRuntimeStatus().enabled;

  const currentFile = fileURLToPath(import.meta.url);
  const projectRoot =
    options.projectRootOverride ?? path.resolve(path.dirname(currentFile), "..", "..", "..");
  const portableMode = options.portable ?? isPackagedInstallRoot(projectRoot);
  const mcpEntrypoint = path
    .join(projectRoot, "dist", "src", "cli", "index.js")
    .replace(/\\/g, "/");
  const serverCommand = portableMode ? "npx" : "node";
  const serverArgs = portableMode ? ["-y", "jev-codeguard", "serve"] : [mcpEntrypoint, "serve"];
  const hookCommand = portableMode
    ? "npx -y jev-codeguard gate"
    : `node "${mcpEntrypoint}" gate`;

  let skillInstalledPath: string | undefined;
  const installedSkillPaths: string[] = [];
  if (options.installSkill !== false) {
    const sourceSkill = path.join(projectRoot, "skills", "jev-system-one", "SKILL.md");
    if (fs.existsSync(sourceSkill)) {
      const targetBases: string[] = [];
      if (options.skillsTargetDir) {
        targetBases.push(options.skillsTargetDir);
      } else {
        targetBases.push(path.join(homeDir, ".gemini", "config", "skills"));
        for (const agentRoot of [".claude", ".cursor", ".codex", ".agents"]) {
          const agentDir = path.join(homeDir, agentRoot);
          if (fs.existsSync(agentDir)) {
            targetBases.push(path.join(agentDir, "skills"));
          }
        }
      }

      for (const targetBase of targetBases) {
        try {
          const targetSkillDir = path.join(targetBase, "jev-system-one");
          fs.mkdirSync(targetSkillDir, { recursive: true });
          const dest = path.join(targetSkillDir, "SKILL.md");
          fs.copyFileSync(sourceSkill, dest);
          installedSkillPaths.push(dest);
          if (!skillInstalledPath) {
            skillInstalledPath = dest;
          }
        } catch {
          // Skip read-only or unavailable agent skill folders
        }
      }
    }
  }

  // Auto-register in Antigravity mcp_config.json if present (preserving existing custom env keys)
  const antigravityMcpPath =
    options.antigravityMcpConfigPath ??
    path.join(homeDir, ".gemini", "antigravity", "mcp_config.json");
  if (!options.skipAutoRegister && fs.existsSync(antigravityMcpPath)) {
    try {
      const parsed = JSON.parse(fs.readFileSync(antigravityMcpPath, "utf8")) as {
        mcpServers?: Record<string, { command?: string; args?: string[]; env?: Record<string, string> }>;
      };
      parsed.mcpServers = parsed.mcpServers ?? {};
      const existingEntry = parsed.mcpServers["mcp-jev"];
      const existingEnv: Record<string, string> =
        existingEntry && typeof existingEntry.env === "object" && existingEntry.env !== null
          ? { ...existingEntry.env }
          : {};
      if (options.autopilot === false) {
        delete existingEnv.JEV_AUTOPILOT;
      }
      parsed.mcpServers["mcp-jev"] = {
        command: serverCommand,
        args: serverArgs,
        env: {
          ...existingEnv,
          JEV_SKILLS_DIR:
            existingEnv.JEV_SKILLS_DIR ??
            path.join(homeDir, ".gemini", "config", "skills").replace(/\\/g, "/")
        }
      };
      fs.writeFileSync(antigravityMcpPath, JSON.stringify(parsed, null, 2), "utf8");
    } catch {
      // Ignore write error if locked
    }
  }

  // Keep JEV_AUTOPILOT out of MCP env snippets so ~/.mcp-jev/config.json and the Live Radar toggle stay unlocked.
  const mcpSnippetEnv: Record<string, string> = {
    JEV_API_KEY: options.apiKey ? "<SAVED_IN_~/.mcp-jev/config.json>" : "jev_live_your_key_here",
    JEV_SKILLS_DIR: path.join(homeDir, ".gemini", "config", "skills").replace(/\\/g, "/")
  };

  const mcpConfigSnippet = JSON.stringify(
    {
      mcpServers: {
        "mcp-jev": {
          command: serverCommand,
          args: serverArgs,
          env: mcpSnippetEnv
        }
      }
    },
    null,
    2
  );

  const codexTomlSnippet = [
    "[mcp_servers.mcp-jev]",
    `command = ${JSON.stringify(serverCommand)}`,
    `args = ${JSON.stringify(serverArgs)}`
  ].join("\n");

  const claudeHookSnippet = JSON.stringify(
    {
      hooks: {
        PreToolUse: [
          {
            matcher: "Bash|Write|Edit",
            hooks: [
              {
                type: "command",
                command: hookCommand
              }
            ]
          }
        ]
      }
    },
    null,
    2
  );

  const agentRulesSnippet = buildAgentRulesSnippet(autopilotEnabled);

  return {
    configSavedPath,
    autopilotEnabled,
    skillInstalledPath,
    installedSkillPaths,
    mcpEntrypoint,
    portableMode,
    mcpConfigSnippet,
    codexTomlSnippet,
    claudeHookSnippet,
    agentRulesSnippet
  };
}
