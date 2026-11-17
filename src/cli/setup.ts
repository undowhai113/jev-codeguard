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
    .optional()
});

export interface SetupOptions {
  apiKey?: string;
  installSkill?: boolean;
  skillsTargetDir?: string;
}

export interface SetupReport {
  configSavedPath?: string;
  skillInstalledPath?: string;
  mcpEntrypoint: string;
  mcpConfigSnippet: string;
  codexTomlSnippet: string;
  claudeHookSnippet: string;
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
  const projectRoot = path.resolve(path.dirname(currentFile), "..", "..", "..");
  const mcpEntrypoint = path
    .join(projectRoot, "dist", "src", "cli", "index.js")
    .replace(/\\/g, "/");

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

  // Auto-register in Antigravity mcp_config.json if present
  const antigravityMcpPath = path.join(homeDir, ".gemini", "antigravity", "mcp_config.json");
  if (fs.existsSync(antigravityMcpPath)) {
    try {
      const parsed = JSON.parse(fs.readFileSync(antigravityMcpPath, "utf8")) as {
        mcpServers?: Record<string, unknown>;
      };
      parsed.mcpServers = parsed.mcpServers ?? {};
      parsed.mcpServers["mcp-jev"] = {
        command: "node",
        args: [mcpEntrypoint, "serve"],
        env: {
          JEV_SKILLS_DIR: path
            .join(homeDir, ".gemini", "config", "skills")
            .replace(/\\/g, "/")
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
          command: "node",
          args: [mcpEntrypoint, "serve"],
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
    'command = "node"',
    `args = ["${mcpEntrypoint}", "serve"]`
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
                command: `node "${mcpEntrypoint}" gate`
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
    mcpConfigSnippet,
    codexTomlSnippet,
    claudeHookSnippet
  };
}
