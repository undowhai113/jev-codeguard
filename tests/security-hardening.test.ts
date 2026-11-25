import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import {
  extractCrossFileContracts,
  extractFileHeaderContext,
  extractPostEditHunkScopes,
  runFastSyntaxProbe
} from "../src/core/context-enricher.js";
import { stripSensitiveDiffSections } from "../src/core/git-collector.js";
import { runSetup, isPackagedInstallRoot } from "../src/cli/setup.js";
import { runPreToolHook } from "../src/cli/hook-runner.js";
import { JevClient } from "../src/core/jev-client.js";
import { TelemetryTracker } from "../src/core/telemetry.js";
import { detectAgentIdentity, readSessionEvents } from "../src/core/event-log.js";
import type { JevResponse } from "../src/core/types.js";

test("context-enricher file readers block path traversal and sensitive files", () => {
  const parentDir = fs.mkdtempSync(path.join(os.tmpdir(), "jev-sec-parent-"));
  const workspaceDir = path.join(parentDir, "workspace");
  fs.mkdirSync(path.join(workspaceDir, "src"), { recursive: true });

  const outsideSecret = path.join(parentDir, "secret.ts");
  fs.writeFileSync(outsideSecret, "export const SECRET_TOKEN = 'super-secret-outside';\n", "utf8");

  const workspaceEnv = path.join(workspaceDir, ".env");
  fs.writeFileSync(workspaceEnv, "DATABASE_URL=postgres://admin:secret@localhost/prod\n", "utf8");

  const safeImporter = path.join(workspaceDir, "src", "app.ts");
  fs.writeFileSync(
    safeImporter,
    'import { SECRET_TOKEN } from "../../secret.js";\nexport const ok = SECRET_TOKEN;\n',
    "utf8"
  );

  try {
    // 1. extractFileHeaderContext must refuse both outside paths and .env inside workspace
    const headers = extractFileHeaderContext(workspaceDir, outsideSecret, [".env", "../secret.ts"]);
    assert.deepEqual(Object.keys(headers), []);

    // 2. extractPostEditHunkScopes must refuse ../ traversal in untrusted inline diffs
    const maliciousDiff = [
      "diff --git a/../secret.ts b/../secret.ts",
      "--- a/../secret.ts",
      "+++ b/../secret.ts",
      "@@ -1,1 +1,1 @@",
      "+export const x = 1;"
    ].join("\n");
    const scopes = extractPostEditHunkScopes(workspaceDir, maliciousDiff);
    assert.deepEqual(Object.keys(scopes), []);

    // 3. extractCrossFileContracts must refuse following imports outside the workspace
    const contracts = extractCrossFileContracts(workspaceDir, ["src/app.ts", "../secret.ts"]);
    assert.equal(
      Object.values(contracts).some((v) => v.includes("super-secret-outside")),
      false
    );

    // 4. runFastSyntaxProbe must skip outside paths and .env files
    const outsideJson = path.join(parentDir, "broken.json");
    fs.writeFileSync(outsideJson, "{ broken", "utf8");
    const probe = runFastSyntaxProbe(workspaceDir, [outsideJson, "../broken.json", ".env"]);
    assert.equal(probe.checkedFiles.length, 0);
    assert.equal(probe.errors.length, 0);
  } finally {
    fs.rmSync(parentDir, { recursive: true, force: true });
  }
});

test("stripSensitiveDiffSections removes tracked .env and private key diffs while keeping normal code", () => {
  const combined = [
    "diff --git a/.env b/.env\n--- a/.env\n+++ b/.env\n@@ -1 +1 @@\n+API_KEY=leak",
    "diff --git a/certs/server.key b/certs/server.key\n--- a/certs/server.key\n+++ b/certs/server.key\n@@ -1 +1 @@\n+-----BEGIN PRIVATE KEY-----",
    "diff --git a/src/app.ts b/src/app.ts\n--- a/src/app.ts\n+++ b/src/app.ts\n@@ -1 +1 @@\n+export const ok = true;"
  ].join("\n\n");

  const sanitized = stripSensitiveDiffSections(combined);
  assert.equal(sanitized.includes("API_KEY=leak"), false);
  assert.equal(sanitized.includes("BEGIN PRIVATE KEY"), false);
  assert.equal(sanitized.includes("export const ok = true;"), true);
});

test("runSetup emits portable npx snippets for _npx/node_modules installs and preserves existing mcp_config env", () => {
  assert.equal(
    isPackagedInstallRoot("C:\\Users\\dev\\AppData\\Local\\npm-cache\\_npx\\abc123\\node_modules\\jev-codeguard"),
    true
  );
  assert.equal(isPackagedInstallRoot("/home/dev/projects/jev-codeguard"), false);

  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "jev-setup-test-"));
  const mcpConfigPath = path.join(tmpDir, "mcp_config.json");
  const skillsDir = path.join(tmpDir, "skills");
  fs.writeFileSync(
    mcpConfigPath,
    JSON.stringify({
      mcpServers: {
        "mcp-jev": {
          command: "node",
          args: ["old"],
          env: {
            JEV_POLICY: "strict",
            JEV_AUTOPILOT: "1"
          }
        }
      }
    }),
    "utf8"
  );

  try {
    const report = runSetup({
      installSkill: true,
      skillsTargetDir: skillsDir,
      portable: true,
      antigravityMcpConfigPath: mcpConfigPath
    });
    assert.equal(report.portableMode, true);
    assert.ok(report.mcpConfigSnippet.includes('"command": "npx"'));
    assert.ok(report.mcpConfigSnippet.includes('"jev-codeguard"'));
    assert.ok(report.claudeHookSnippet.includes("npx -y jev-codeguard gate"));
    assert.ok(report.codexTomlSnippet.includes('command = "npx"'));

    const updated = JSON.parse(fs.readFileSync(mcpConfigPath, "utf8")) as {
      mcpServers: { "mcp-jev": { command: string; args: string[]; env: Record<string, string> } };
    };
    assert.equal(updated.mcpServers["mcp-jev"].command, "npx");
    assert.deepEqual(updated.mcpServers["mcp-jev"].args, ["-y", "jev-codeguard", "serve"]);
    assert.equal(updated.mcpServers["mcp-jev"].env.JEV_POLICY, "strict");
    assert.equal(updated.mcpServers["mcp-jev"].env.JEV_AUTOPILOT, "1");
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test("runPreToolHook records code-write audit events to session log", async () => {
  const tmpEvents = path.join(os.tmpdir(), `jev-hook-code-audit-${Date.now()}.jsonl`);
  process.env.JEV_EVENTS_FILE = tmpEvents;
  const mockFetch: typeof fetch = async () => {
    const payload: JevResponse = {
      model: "jev-1.14.0",
      answers: {
        overall_security_score: { type: "score", score: 1.5, probabilities: { "1": 0.6, "2": 0.4 } },
        injection_sql_cmd_path: { type: "noul", noul: 0.92 }
      }
    };
    return new Response(JSON.stringify(payload), { status: 200 });
  };
  const client = new JevClient({ apiKey: "jev_test_key", fetchImpl: mockFetch, retryDelayMs: 1 });

  try {
    const res = await runPreToolHook(
      JSON.stringify({
        tool_name: "Write",
        tool_input: {
          file_path: "src/db.ts",
          content: "const sql = `SELECT * FROM users WHERE id = ${req.params.id}`;"
        }
      }),
      client
    );
    assert.equal(res.exitCode, 2);
    assert.equal(res.verdict, "BLOCK");

    const logged = readSessionEvents(5);
    assert.equal(logged.length, 1);
    assert.equal(logged[0].tool, "jev_audit_code");
    assert.equal(logged[0].verdict, "BLOCK");
  } finally {
    if (fs.existsSync(tmpEvents)) fs.unlinkSync(tmpEvents);
    delete process.env.JEV_EVENTS_FILE;
  }
});

test("JevClient handles invalid JEV_TIMEOUT_MS gracefully and TelemetryTracker bounds recentEvents", async () => {
  const prevTimeout = process.env.JEV_TIMEOUT_MS;
  process.env.JEV_TIMEOUT_MS = "not-a-number";
  try {
    const client = new JevClient({
      apiKey: "jev_test_key",
      fetchImpl: async () =>
        new Response(
          JSON.stringify({
            model: "jev-1.14.0",
            answers: { ok: { type: "noul", noul: 0.9 } }
          }),
          { status: 200 }
        )
    });
    const out = await client.evaluate({ a: 1 }, { ok: { type: "noul", instructions: "ok?" } });
    assert.equal(out.response.model, "jev-1.14.0");
  } finally {
    if (prevTimeout === undefined) delete process.env.JEV_TIMEOUT_MS;
    else process.env.JEV_TIMEOUT_MS = prevTimeout;
  }

  const tracker = new TelemetryTracker(5);
  for (let i = 0; i < 20; i += 1) {
    tracker.record({
      operation: `op-${i}`,
      latencyMs: 100,
      cached: i % 2 === 0,
      inputTokens: 10,
      outputTokens: 0,
      costUsd: 0.0001,
      verdict: "ALLOW"
    });
  }
  const summary = tracker.getSummary();
  assert.equal(summary.totalCalls, 20);
  assert.equal(summary.cacheHits, 10);
  assert.equal(summary.apiCalls, 10);
  assert.equal(summary.recentEvents.length, 5);
  assert.equal(summary.recentEvents[4].operation, "op-19");

  assert.equal(detectAgentIdentity("Claude Code"), "Claude");
  assert.equal(detectAgentIdentity("Cursor IDE"), "Cursor");
});
