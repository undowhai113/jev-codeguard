import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { runPreToolHook } from "../src/cli/hook-runner.js";
import { JevClient } from "../src/core/jev-client.js";
import type { JevResponse } from "../src/core/types.js";

function createStubClient(verdictMode: "safe" | "dangerous" | "error"): JevClient {
  const mockFetch: typeof fetch = async () => {
    if (verdictMode === "error") {
      return new Response("Internal Server Error", { status: 500 });
    }
    const isSafe = verdictMode === "safe";
    const payload: JevResponse = {
      model: "jev-1.14.0",
      answers: {
        is_safe_to_execute: { type: "noul", noul: isSafe ? 0.97 : 0.08 },
        is_destructive_or_irreversible: { type: "noul", noul: isSafe ? 0.01 : 0.94 },
        exposes_secrets_or_network_risk: { type: "noul", noul: isSafe ? 0.01 : 0.45 },
        blast_radius: {
          type: "score",
          score: isSafe ? 1.1 : 4.9,
          probabilities: isSafe ? { "1": 0.9, "2": 0.1 } : { "5": 0.9, "4": 0.1 }
        },
        recommended_decision: {
          type: "choice",
          selected: isSafe ? "allow_silently" : "block_immediately",
          probabilities: isSafe
            ? { allow_silently: 0.96, ask_user_confirmation: 0.03, block_immediately: 0.01 }
            : { allow_silently: 0.01, ask_user_confirmation: 0.04, block_immediately: 0.95 }
        }
      }
    };
    return new Response(JSON.stringify(payload), { status: 200 });
  };

  return new JevClient({
    apiKey: "jev_hook_test_key",
    fetchImpl: mockFetch,
    retryDelayMs: 1
  });
}

test("runPreToolHook returns exitCode 0 (ALLOW) for safe commands and ASK_USER for prose", async () => {
  const tmpEvents = path.join(os.tmpdir(), `jev-hook-test-${Date.now()}.jsonl`);
  process.env.JEV_EVENTS_FILE = tmpEvents;
  try {
    const client = createStubClient("safe");
    const result = await runPreToolHook(
      JSON.stringify({
        tool_name: "Bash",
        tool_input: { command: "git status" }
      }),
      client
    );

    assert.equal(result.exitCode, 0);
    assert.equal(result.verdict, "ALLOW");
    assert.ok(result.stdout.includes('"permissionDecision":"allow"'));

    const proseResult = await runPreToolHook(
      JSON.stringify({
        tool_name: "Bash",
        tool_input: {
          command: "Commit only four documentation files on the existing branch without pushing."
        }
      }),
      client
    );
    assert.equal(proseResult.exitCode, 0);
    assert.equal(proseResult.verdict, "ASK_USER");
    assert.ok(proseResult.stdout.includes('"permissionDecision":"ask"'));
  } finally {
    if (fs.existsSync(tmpEvents)) fs.unlinkSync(tmpEvents);
    delete process.env.JEV_EVENTS_FILE;
  }
});

test("runPreToolHook returns exitCode 2 (BLOCK) with stderr remediation for destructive commands", async () => {
  const tmpEvents = path.join(os.tmpdir(), `jev-hook-block-${Date.now()}.jsonl`);
  process.env.JEV_EVENTS_FILE = tmpEvents;
  try {
    const client = createStubClient("dangerous");
    const result = await runPreToolHook(
      JSON.stringify({
        tool_name: "Bash",
        tool_input: { command: "rm -rf / --no-preserve-root" }
      }),
      client
    );

    assert.equal(result.exitCode, 2);
    assert.equal(result.verdict, "BLOCK");
    assert.ok(result.stderr.includes("BLOCK"));
  } finally {
    if (fs.existsSync(tmpEvents)) fs.unlinkSync(tmpEvents);
    delete process.env.JEV_EVENTS_FILE;
  }
});

test("runPreToolHook respects fail-open/ask fallback when Jev API is unreachable", async () => {
  const client = createStubClient("error");
  const result = await runPreToolHook(
    JSON.stringify({
      tool_name: "Bash",
      tool_input: { command: "npm run build" }
    }),
    client,
    "ask"
  );

  assert.equal(result.exitCode, 0);
  assert.equal(result.verdict, "ASK_USER");
  assert.ok(result.stdout.includes('"permissionDecision":"ask"'));
});
