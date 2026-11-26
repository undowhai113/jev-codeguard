import test from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import {
  getAutopilotRuntimeStatus,
  readRuntimeConfig,
  updateRuntimeConfig
} from "../src/core/runtime-config.js";
import { isAutopilotEnabled } from "../src/core/policy-config.js";
import { runSetup } from "../src/cli/setup.js";
import { startDashboardServer } from "../src/dashboard/server.js";
import { McpJevDispatcher } from "../src/mcp/server.js";
import { JevClient } from "../src/core/jev-client.js";
import type { JevResponse } from "../src/core/types.js";

test("runtime-config persists autopilot atomically, guards synthetic env and corrupt JSON", () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "jev-rt-cfg-"));
  const cfgPath = path.join(tmpDir, "config.json");
  try {
    const baseEnv: NodeJS.ProcessEnv = { JEV_CONFIG_PATH: cfgPath };

    // Default: off
    assert.equal(isAutopilotEnabled(baseEnv), false);
    assert.equal(getAutopilotRuntimeStatus(baseEnv).source, "default");

    // Save apiKey first, then toggle autopilot -> apiKey must remain intact
    updateRuntimeConfig({ apiKey: "jev_live_secret_123456" }, baseEnv);
    updateRuntimeConfig({ autopilot: true }, baseEnv);

    const saved = readRuntimeConfig(baseEnv);
    assert.equal(saved.apiKey, "jev_live_secret_123456");
    assert.equal(saved.autopilot, true);
    assert.equal(isAutopilotEnabled(baseEnv), true);
    assert.equal(getAutopilotRuntimeStatus(baseEnv).source, "config");
    assert.equal(getAutopilotRuntimeStatus(baseEnv).envLocked, false);

    // Explicit env overrides config.json both ways
    assert.equal(isAutopilotEnabled({ ...baseEnv, JEV_AUTOPILOT: "0" }), false);
    assert.equal(getAutopilotRuntimeStatus({ ...baseEnv, JEV_AUTOPILOT: "0" }).envLocked, true);
    assert.equal(isAutopilotEnabled({ ...baseEnv, JEV_AUTOPILOT: "1" }), true);

    // Toggling back off preserves apiKey
    updateRuntimeConfig({ autopilot: false }, baseEnv);
    assert.equal(readRuntimeConfig(baseEnv).apiKey, "jev_live_secret_123456");
    assert.equal(isAutopilotEnabled(baseEnv), false);

    // Synthetic empty env stays isolated: read is false and write throws instead of touching host config
    assert.equal(isAutopilotEnabled({}), false);
    assert.throws(() => updateRuntimeConfig({ autopilot: true }, {}), /Cannot resolve runtime config path/);

    // Corrupt existing config must throw instead of silently overwriting apiKey
    fs.writeFileSync(cfgPath, "{ malformed json", "utf8");
    assert.throws(() => updateRuntimeConfig({ autopilot: true }, baseEnv));
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test("Dashboard /api/settings toggles persistent autopilot with CSRF, SSE sync, and never leaks apiKey", async () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "jev-dash-ap-"));
  const cfgPath = path.join(tmpDir, "config.json");
  const prevCfg = process.env.JEV_CONFIG_PATH;
  const prevAp = process.env.JEV_AUTOPILOT;
  process.env.JEV_CONFIG_PATH = cfgPath;
  delete process.env.JEV_AUTOPILOT;

  updateRuntimeConfig({ apiKey: "jev_live_never_expose_me" });
  const { url, server } = await startDashboardServer({ port: 0 });
  const sseAbort = new AbortController();
  try {
    const html = await (await fetch(url)).text();
    const csrfMatch = html.match(/const JEV_CSRF_TOKEN = "([a-f0-9]{48})";/);
    assert.ok(csrfMatch, "Dashboard HTML must embed CSRF token");
    const csrfToken = csrfMatch[1];
    assert.ok(html.includes('id="btnAutopilotToggle"'), "Dashboard must render Autopilot toggle switch");
    assert.ok(html.includes(".bar-fill.Claude") && html.includes(".bar-fill.Cursor"));

    // GET /api/settings must return default false and never leak apiKey
    const getRes = await fetch(`${url}/api/settings`);
    assert.equal(getRes.status, 200);
    const getRaw = await getRes.text();
    assert.equal(getRaw.includes("jev_live_never_expose_me"), false, "apiKey must never leak in /api/settings");
    const getJson = JSON.parse(getRaw) as {
      ok: boolean;
      autopilotEnabled: boolean;
      source: string;
      envLocked: boolean;
    };
    assert.equal(getJson.ok, true);
    assert.equal(getJson.autopilotEnabled, false);
    assert.equal(getJson.envLocked, false);

    // Connect an SSE listener to verify live settings_updated broadcast
    const sseRes = await fetch(`${url}/api/stream`, { signal: sseAbort.signal });
    const reader = sseRes.body?.getReader();
    assert.ok(reader, "SSE stream must open");

    // POST without CSRF must be blocked (403)
    const badCsrf = await fetch(`${url}/api/settings`, {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-Jev-CSRF": "forged" },
      body: JSON.stringify({ autopilotEnabled: true })
    });
    assert.equal(badCsrf.status, 403);

    // POST with valid CSRF enables autopilot persistently while preserving apiKey
    const enableRes = await fetch(`${url}/api/settings`, {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-Jev-CSRF": csrfToken },
      body: JSON.stringify({ autopilotEnabled: true })
    });
    assert.equal(enableRes.status, 200);
    const enableJson = (await enableRes.json()) as { ok: boolean; autopilotEnabled: boolean; source: string };
    assert.equal(enableJson.ok, true);
    assert.equal(enableJson.autopilotEnabled, true);
    assert.equal(enableJson.source, "config");
    assert.equal(readRuntimeConfig().apiKey, "jev_live_never_expose_me");
    assert.equal(readRuntimeConfig().autopilot, true);

    // Confirm SSE broadcast delivered settings_updated
    const decoder = new TextDecoder();
    let sseBuf = "";
    for (let i = 0; i < 6 && !sseBuf.includes("settings_updated"); i += 1) {
      const chunk = await Promise.race([
        reader.read(),
        new Promise<{ done: true; value: undefined }>((r) => setTimeout(() => r({ done: true, value: undefined }), 500))
      ]);
      if (chunk.value) sseBuf += decoder.decode(chunk.value);
      if (chunk.done) break;
    }
    assert.ok(sseBuf.includes('"type":"settings_updated"'), "SSE must broadcast settings_updated");

    // When JEV_AUTOPILOT env var is set, POST /api/settings returns 409 conflict
    process.env.JEV_AUTOPILOT = "0";
    const lockedRes = await fetch(`${url}/api/settings`, {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-Jev-CSRF": csrfToken },
      body: JSON.stringify({ autopilotEnabled: true })
    });
    assert.equal(lockedRes.status, 409);
    const lockedJson = (await lockedRes.json()) as { envLocked: boolean; autopilotEnabled: boolean };
    assert.equal(lockedJson.envLocked, true);
    assert.equal(lockedJson.autopilotEnabled, false);
  } finally {
    sseAbort.abort();
    server.close();
    if (prevCfg === undefined) delete process.env.JEV_CONFIG_PATH;
    else process.env.JEV_CONFIG_PATH = prevCfg;
    if (prevAp === undefined) delete process.env.JEV_AUTOPILOT;
    else process.env.JEV_AUTOPILOT = prevAp;
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test("setup --autopilot / --no-autopilot keeps Live Radar unlocked, emits agent rules, and live-toggles autopilotDecide", async () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "jev-setup-ap-"));
  const cfgPath = path.join(tmpDir, "config.json");
  const eventsPath = path.join(tmpDir, "events.jsonl");
  const skillsDir = path.join(tmpDir, "skills");
  const agConfig = path.join(tmpDir, "mcp_config.json");
  fs.writeFileSync(
    agConfig,
    JSON.stringify({
      mcpServers: {
        "mcp-jev": { command: "npx", args: ["-y", "jev-codeguard", "serve"], env: { JEV_AUTOPILOT: "1" } }
      }
    }),
    "utf8"
  );

  const prevCfg = process.env.JEV_CONFIG_PATH;
  const prevEvents = process.env.JEV_EVENTS_FILE;
  const prevAp = process.env.JEV_AUTOPILOT;
  process.env.JEV_CONFIG_PATH = cfgPath;
  process.env.JEV_EVENTS_FILE = eventsPath;
  delete process.env.JEV_AUTOPILOT;

  const mockFetch: typeof fetch = async () => {
    const payload: JevResponse = {
      model: "jev-test",
      answers: {
        selected_option: { type: "choice", selected: "A", probabilities: { A: 0.94, B: 0.06 } },
        is_reversible_technical_choice: { type: "noul", noul: 0.92 },
        requires_private_business_or_human_taste: { type: "noul", noul: 0.08 },
        alignment_strength: { type: "score", score: 4.5, probabilities: {} }
      }
    };
    return new Response(JSON.stringify(payload), { status: 200 });
  };

  try {
    const report = runSetup({
      apiKey: "jev_live_setup_key_01",
      autopilot: true,
      portable: true,
      skipAutoRegister: true,
      skillsTargetDir: skillsDir
    });
    assert.equal(report.autopilotEnabled, true);
    // Snippet must NOT hardcode JEV_AUTOPILOT so Live Radar :4399 toggle remains unlocked
    assert.equal(report.mcpConfigSnippet.includes("JEV_AUTOPILOT"), false);
    assert.ok(report.agentRulesSnippet.includes("jev_autopilot_decide"));
    assert.ok(report.agentRulesSnippet.includes("AUTOPILOT_PROCEED"));
    assert.equal(readRuntimeConfig().autopilot, true);
    assert.equal(readRuntimeConfig().apiKey, "jev_live_setup_key_01");

    // Live dispatcher picks up config.json autopilot=true without env var
    const client = new JevClient({ apiKey: "jev_live_setup_key_01", fetchImpl: mockFetch });
    const dispatcher = new McpJevDispatcher(client);
    const resOn = await dispatcher.autopilotDecide({
      question: "Use Vitest or native node:test?",
      options: { A: "node:test (zero deps)", B: "Vitest" },
      working_directory: tmpDir
    });
    assert.equal(resOn.mode, "AUTOPILOT_PROCEED");
    assert.equal(resOn.selectedOption, "A");

    // --no-autopilot clears stale JEV_AUTOPILOT env from Antigravity mcp_config.json and disables config
    const offReport = runSetup({
      autopilot: false,
      portable: true,
      antigravityMcpConfigPath: agConfig,
      skillsTargetDir: skillsDir
    });
    assert.equal(offReport.autopilotEnabled, false);
    const updatedAg = JSON.parse(fs.readFileSync(agConfig, "utf8")) as {
      mcpServers: { "mcp-jev": { env: Record<string, string> } };
    };
    assert.equal(updatedAg.mcpServers["mcp-jev"].env.JEV_AUTOPILOT, undefined);

    const resOff = await dispatcher.autopilotDecide({
      question: "Use Vitest or native node:test?",
      options: { A: "node:test (zero deps)", B: "Vitest" },
      working_directory: tmpDir
    });
    assert.equal(resOff.mode, "ASK_HUMAN");
    assert.equal(resOff.escalationReason, "autopilot_disabled");

    // CLI autopilot-mode on/off/status & invalid action rejection
    const cliEntry = path.resolve(process.cwd(), "dist/src/cli/index.js");
    const cliEnv: NodeJS.ProcessEnv = { ...process.env, JEV_CONFIG_PATH: cfgPath };
    delete cliEnv.JEV_AUTOPILOT;
    execFileSync(process.execPath, [cliEntry, "autopilot-mode", "on"], { env: cliEnv, encoding: "utf8" });
    assert.equal(readRuntimeConfig(cliEnv).autopilot, true);
    const statusOut = execFileSync(process.execPath, [cliEntry, "autopilot-mode", "status"], {
      env: cliEnv,
      encoding: "utf8"
    });
    assert.equal((JSON.parse(statusOut) as { enabled: boolean }).enabled, true);
    assert.throws(() =>
      execFileSync(process.execPath, [cliEntry, "autopilot-mode", "typo-action"], {
        env: cliEnv,
        stdio: "pipe"
      })
    );
  } finally {
    if (prevCfg === undefined) delete process.env.JEV_CONFIG_PATH;
    else process.env.JEV_CONFIG_PATH = prevCfg;
    if (prevEvents === undefined) delete process.env.JEV_EVENTS_FILE;
    else process.env.JEV_EVENTS_FILE = prevEvents;
    if (prevAp === undefined) delete process.env.JEV_AUTOPILOT;
    else process.env.JEV_AUTOPILOT = prevAp;
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});
