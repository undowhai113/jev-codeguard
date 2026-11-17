import test from "node:test";
import assert from "node:assert/strict";
import os from "node:os";
import path from "node:path";
import fs from "node:fs";
import { spawn } from "node:child_process";
import {
  clearSessionEvents,
  detectAgentIdentity,
  getRotatedEventsFilePath,
  readSessionEvents,
  recordSessionEvent
} from "../src/core/event-log.js";
import { startDashboardServer } from "../src/dashboard/server.js";

function sampleEvent(seq: number, agent = "Codex") {
  return {
    agent,
    workspace: "MCP-Jev",
    tool: "jev_guard_action",
    questionOrTitle: `seq-${seq}`,
    optionsOrInput: { command: "npm test", seq: String(seq) },
    verdict: "ALLOW" as const,
    selectedOption: "ALLOW",
    selectedProbability: 0.9,
    probabilities: { safe_probability: 0.9 },
    directive: "ok",
    latencyMs: 1,
    costUsd: 0,
    cached: false
  };
}

function countLines(file: string): number {
  if (!fs.existsSync(file)) return 0;
  return fs
    .readFileSync(file, "utf8")
    .split(/\r?\n/)
    .filter((l) => l.trim()).length;
}

test("concurrent writers from separate processes never lose events (no read-trim-rewrite)", async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "jev-events-concurrency-"));
  const file = path.join(dir, "events.jsonl");
  const moduleUrl = new URL("../src/core/event-log.js", import.meta.url).href;
  // 4 x 120 = 480 events: above the old 350-line trim point that rewrote the file.
  const writers = 4;
  const perWriter = 120;
  const script = `
    const { recordSessionEvent } = await import(${JSON.stringify(moduleUrl)});
    for (let i = 0; i < ${perWriter}; i += 1) {
      recordSessionEvent({
        agent: "Codex", workspace: "w", tool: "jev_guard_action",
        questionOrTitle: process.env.WRITER + "-" + i, optionsOrInput: {}, verdict: "ALLOW",
        selectedOption: "ALLOW", selectedProbability: 1, probabilities: {}, directive: "",
        latencyMs: 0, costUsd: 0, cached: false
      });
    }`;
  try {
    await Promise.all(
      Array.from({ length: writers }, (_, w) =>
        new Promise<void>((resolve, reject) => {
          const child = spawn(process.execPath, ["--input-type=module", "-e", script], {
            env: { ...process.env, JEV_EVENTS_FILE: file, WRITER: `w${w}` },
            stdio: ["ignore", "ignore", "pipe"]
          });
          let stderr = "";
          child.stderr.on("data", (d) => (stderr += d));
          child.on("exit", (code) => (code === 0 ? resolve() : reject(new Error(stderr))));
        })
      )
    );
    const lines = fs.readFileSync(file, "utf8").split(/\r?\n/).filter((l) => l.trim());
    assert.equal(lines.length, writers * perWriter);
    const titles = new Set(lines.map((l) => (JSON.parse(l) as { questionOrTitle: string }).questionOrTitle));
    assert.equal(titles.size, writers * perWriter, "every event must survive exactly once");
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("events.jsonl rotates to events.1.jsonl past the size cap and reads span both files", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "jev-events-rotate-"));
  const file = path.join(dir, "events.jsonl");
  const rotated = getRotatedEventsFilePath(file);
  process.env.JEV_EVENTS_FILE = file;
  process.env.JEV_EVENTS_MAX_BYTES = "4096";
  try {
    assert.equal(rotated, path.join(dir, "events.1.jsonl"));
    let seq = 0;
    while (!fs.existsSync(rotated)) {
      recordSessionEvent(sampleEvent(seq));
      seq += 1;
      assert.ok(seq < 1000, "rotation never happened");
    }
    // The event that triggered rotation is the first line of the fresh events.jsonl.
    const firstRotationLines = countLines(rotated);
    assert.equal(countLines(file), 1);
    for (let i = 0; i < 5; i += 1) recordSessionEvent(sampleEvent(seq++));

    assert.ok(fs.statSync(rotated).size >= 4096);
    assert.ok(fs.statSync(file).size < 4096);
    assert.equal(countLines(rotated), firstRotationLines, "rotated file is never rewritten");
    assert.equal(countLines(file), 6);
    const total = countLines(file) + countLines(rotated);

    // Newest first, contiguous across the rotation boundary, nothing lost or duplicated.
    const events = readSessionEvents(total);
    assert.equal(events.length, total);
    const seqs = events.map((e) => Number(e.optionsOrInput.seq));
    assert.equal(seqs[0], seq - 1);
    for (let i = 1; i < seqs.length; i += 1) {
      assert.equal(seqs[i], seqs[i - 1] - 1);
    }
    assert.equal(readSessionEvents(3).length, 3);
    assert.equal(Number(readSessionEvents(1)[0].optionsOrInput.seq), seq - 1);

    clearSessionEvents();
    assert.equal(readSessionEvents(10).length, 0);
    assert.equal(fs.existsSync(rotated), false);
  } finally {
    delete process.env.JEV_EVENTS_FILE;
    delete process.env.JEV_EVENTS_MAX_BYTES;
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("detectAgentIdentity distinguishes Codex, Gemini, and CLI", () => {
  assert.equal(detectAgentIdentity("Codex"), "Codex");
  assert.equal(detectAgentIdentity("OpenAI Codex"), "Codex");
  assert.equal(detectAgentIdentity("Gemini (Antigravity)"), "Gemini");
  assert.equal(detectAgentIdentity("CLI"), "CLI");
});

test("recordSessionEvent and readSessionEvents persist cross-process events", () => {
  const tmpFile = path.join(os.tmpdir(), `jev-test-events-${Date.now()}.jsonl`);
  process.env.JEV_EVENTS_FILE = tmpFile;

  try {
    clearSessionEvents();
    recordSessionEvent({
      agent: "Codex",
      workspace: "acme-inventory-api",
      tool: "jev_autopilot_decide",
      questionOrTitle: "Which lock strategy?",
      optionsOrInput: { A: "Prisma transaction", B: "Redis lock" },
      verdict: "AUTOPILOT_PROCEED",
      selectedOption: "A",
      selectedProbability: 0.94,
      probabilities: { A: 0.94, B: 0.06 },
      directive: "Proceed with A",
      latencyMs: 142,
      costUsd: 0.00018,
      cached: false
    });

    recordSessionEvent({
      agent: "Gemini",
      workspace: "MCP-Jev",
      tool: "jev_verify_diff",
      questionOrTitle: "Verify diff against spec",
      optionsOrInput: { spec: "Add live radar portal" },
      verdict: "ALLOW",
      selectedOption: "ALLOW",
      selectedProbability: 0.96,
      probabilities: { spec_fulfilled: 0.96 },
      directive: "Approved",
      latencyMs: 155,
      costUsd: 0.00018,
      cached: false
    });

    const events = readSessionEvents(10);
    assert.equal(events.length, 2);
    assert.equal(events[0].agent, "Gemini");
    assert.equal(events[1].agent, "Codex");
  } finally {
    if (fs.existsSync(tmpFile)) {
      fs.unlinkSync(tmpFile);
    }
    delete process.env.JEV_EVENTS_FILE;
  }
});

test("startDashboardServer serves HTML portal, /api/events JSON, and enforces cryptographic CSRF token", async () => {
  const { url, server } = await startDashboardServer({ port: 0 });
  try {
    const htmlRes = await fetch(url);
    assert.equal(htmlRes.status, 200);
    assert.ok(htmlRes.headers.get("content-security-policy")?.includes("default-src 'self'"));
    const htmlText = await htmlRes.text();
    assert.ok(htmlText.includes("SYSTEM-1 ONLINE"));
    assert.ok(htmlText.includes('id="btnLangEn"') && htmlText.includes('id="btnLangVi"'));
    const tokenMatch = htmlText.match(/const JEV_CSRF_TOKEN = "([a-f0-9]{48})";/);
    assert.ok(tokenMatch, "Dashboard HTML must embed per-boot cryptographic CSRF token");

    const apiRes = await fetch(`${url}/api/events`);
    assert.equal(apiRes.status, 200);
    const apiJson = (await apiRes.json()) as { stats: { totalEvents: number } };
    assert.equal(typeof apiJson.stats.totalEvents, "number");

    // Static or forged CSRF token must be rejected with 403
    const forgedRes = await fetch(`${url}/api/feedback`, {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-Jev-CSRF": "1" },
      body: JSON.stringify({ workspaceName: "test-ws", rule: "should fail" })
    });
    assert.equal(forgedRes.status, 403);
  } finally {
    server.close();
  }
});
