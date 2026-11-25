import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { z } from "zod";

const SetupOptionsSchema = z.object({
  apiKey: z
    .string()
    .trim()
    .min(8, "API key must be at least 8 characters")
    .max(256, "API key exceeds maximum length")
    .regex(/^[A-Za-z0-9_.-]+$/, "API key contains invalid characters")
    .optional(),
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
  installSkill?: boolean;
  skillsTargetDir?: string;
  portable?: boolean;
  skipAutoRegister?: boolean;
  antigravityMcpConfigPath?: string;
  projectRootOverride?: string;
}

export interface SetupReport {
  configSavedPath?: string;
  skillInstalledPath?: string;
  mcpEntrypoint: string;
  portableMode: boolean;
  mcpConfigSnippet: string;
  codexTomlSnippet: string;
  claudeHookSnippet: string;
}

export function isPackagedInstallRoot(rootDir: string): boolean {
  const normalized = rootDir.replace(/\\/g, "/");
  return /\/_npx\/|\/node_modules\//i.test(normalized);
}

export function runSetup(rawOptions: SetupOptions = {}): SetupReport {
  const options = SetupOptionsSchema.parse({
    ...rawOptions,
    apiKey: rawOptions.apiKey && rawOptions.apiKey.trim().length > 0 ? rawOptions.apiKey : undefined
  });
  const homeDir = os.homedir();
  const configDir = path.join(homeDir, ".mcp-jev");
  let configSavedPath: string | undefined;

  if (options.apiKey) {
    fs.mkdirSync(configDir, { recursive: true, mode: 0o700 });
    configSavedPath = path.join(configDir, "config.json");
    fs.writeFileSync(
      configSavedPath,
      JSON.stringify({ apiKey: options.apiKey, updatedAt: new Date().toISOString() }, null, 2),
      { encoding: "utf8", mode: 0o600 }
    );
    try {
      fs.chmodSync(configSavedPath, 0o600);
    } catch {
      // chmod may be a no-op on Windows NTFS
    }
  }

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
  if (options.installSkill !== false) {
    const sourceSkill = path.join(projectRoot, "skills", "jev-system-one", "SKILL.md");
    const targetBase =
      options.skillsTargetDir ?? path.join(homeDir, ".gemini", "config", "skills");
    if (fs.existsSync(sourceSkill)) {
      const targetSkillDir = path.join(targetBase, "jev-system-one");
      fs.mkdirSync(targetSkillDir, { recursive: true });
      skillInstalledPath = path.join(targetSkillDir, "SKILL.md");
      fs.copyFileSync(sourceSkill, skillInstalledPath);
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
      const existingEnv =
        existingEntry && typeof existingEntry.env === "object" && existingEntry.env !== null
          ? existingEntry.env
          : {};
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

  const mcpConfigSnippet = JSON.stringify(
    {
      mcpServers: {
        "mcp-jev": {
          command: serverCommand,
          args: serverArgs,
          env: {
            JEV_API_KEY: options.apiKey ? "<SAVED_IN_~/.mcp-jev/config.json>" : "jev_live_your_key_here",
            JEV_SKILLS_DIR: path
              .join(homeDir, ".gemini", "config", "skills")
              .replace(/\\/g, "/")
          }
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

  return {
    configSavedPath,
    skillInstalledPath,
    mcpEntrypoint,
    portableMode,
    mcpConfigSnippet,
    codexTomlSnippet,
    claudeHookSnippet
  };
}
