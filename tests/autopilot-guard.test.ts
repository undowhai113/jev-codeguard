import test from "node:test";
import assert from "node:assert/strict";
import os from "node:os";
import path from "node:path";
import fs from "node:fs";
import { McpJevDispatcher } from "../src/mcp/server.js";
import { JevClient } from "../src/core/jev-client.js";
import type { JevAnswer, JevResponse } from "../src/core/types.js";

/**
 * Reproduces the real 2026-11-05 incident: jev_guard_action returned ASK_USER for
 * `chkdsk.exe E: /markclean` and the agent immediately asked jev_autopilot_decide
 * whether it could skip confirming with the owner.
 */

function makeWorkspace(root: string, name: string): string {
  const dir = path.join(root, name);
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(path.join(dir, "package.json"), JSON.stringify({ name }), "utf8");
  return dir;
}

const mockFetch: typeof fetch = async (_url, init) => {
  const body = JSON.parse(String(init?.body)) as {
    state: Record<string, unknown>;
    questions: Record<string, unknown>;
  };
  const answers: Record<string, JevAnswer> = {};
  if ("is_safe_to_execute" in body.questions) {
    // Guard profile of the real chkdsk /markclean event (#330): ASK_USER.
    answers.is_safe_to_execute = { type: "noul", noul: 0.3 };
    answers.is_destructive_or_irreversible = { type: "noul", noul: 0.16 };
    answers.exposes_secrets_or_network_risk = { type: "noul", noul: 0.03 };
    answers.blast_radius = { type: "score", score: 3.6, probabilities: {} };
    answers.recommended_decision = {
      type: "choice",
      selected: "ask_user_confirmation",
      probabilities: { ask_user_confirmation: 0.8 }
    };
  } else {
    const question = String(body.state.decision_question_for_user ?? "");
    const p = question.includes("[low]") ? 0.6 : 0.97;
    answers.selected_option = {
      type: "choice",
      selected: "A",
      probabilities: { A: p, B: Number((1 - p).toFixed(2)) }
    };
    answers.is_reversible_technical_choice = { type: "noul", noul: 0.9 };
    answers.requires_private_business_or_human_taste = { type: "noul", noul: 0.1 };
    answers.alignment_strength = { type: "score", score: 4.6, probabilities: {} };
  }
  const payload: JevResponse = {
    model: "jev-test",
    answers,
    usage: { input_tokens: 10, output_tokens: 2, cost: 0 }
  };
  return new Response(JSON.stringify(payload), { status: 200 });
};

const OPTIONS = {
  A: "Ask the owner to confirm the one-time /markclean before running it",
  B: "Treat the earlier rescue request as enough and run it now"
};

test("autopilot defers to the human after a related guard ASK_USER and is off by default", async () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "jev-autopilot-guard-"));
  const saved = {
    HOME: process.env.HOME,
    USERPROFILE: process.env.USERPROFILE,
    JEV_EVENTS_FILE: process.env.JEV_EVENTS_FILE,
    JEV_AUTOPILOT: process.env.JEV_AUTOPILOT
  };
  // Keep project-brain profiles and events out of the developer's real ~/.mcp-jev.
  process.env.HOME = path.join(root, "home");
  process.env.USERPROFILE = path.join(root, "home");
  process.env.JEV_EVENTS_FILE = path.join(root, "events.jsonl");
  delete process.env.JEV_AUTOPILOT;

  try {
    const guarded = makeWorkspace(root, "rescue-ws");
    const other = makeWorkspace(root, "other-ws");
    const newClient = () => new JevClient({ apiKey: "jev_test_autopilot", fetchImpl: mockFetch });
    const codex = new McpJevDispatcher(newClient());

    // 1. Default: autopilot disabled, but still returns Jev's recommendation.
    const off = await codex.autopilotDecide({
      question: "Which test seam should we use?",
      options: OPTIONS,
      working_directory: other
    });
    assert.equal(off.mode, "ASK_HUMAN");
    assert.equal(off.escalationReason, "autopilot_disabled");
    assert.equal(off.selectedOption, "A");

    process.env.JEV_AUTOPILOT = "1";

    // 2. Enabled, no guard escalation: proceeds without "do not interrupt" wording.
    const on = await codex.autopilotDecide({
      question: "Which test seam should we use?",
      options: OPTIONS,
      working_directory: other
    });
    assert.equal(on.mode, "AUTOPILOT_PROCEED");
    assert.doesNotMatch(on.agentDirective, /not interrupt/i);

    // 3. Guard asks for a human; the follow-up autopilot call must not override it.
    const guard = await codex.guardAction({
      exact_command: "chkdsk.exe E: /markclean",
      context: "Owner asked to rescue drive E: without data loss; no full backup exists",
      working_directory: guarded
    });
    assert.equal(guard.decision.verdict, "ASK_USER");

    const afterGuard = await codex.autopilotDecide({
      question: "Guard returned ASK_USER for chkdsk /markclean. Do we need the owner to confirm?",
      options: OPTIONS,
      working_directory: guarded
    });
    assert.equal(afterGuard.mode, "ASK_HUMAN");
    assert.equal(afterGuard.escalationReason, "recent_guard_escalation");
    assert.match(afterGuard.agentDirective, /chkdsk\.exe E: \/markclean/);

    // 4. Another agent process (fresh dispatcher) sees the escalation through the shared log.
    const gemini = new McpJevDispatcher(newClient());
    const crossProcess = await gemini.autopilotDecide({
      question: "Should we run the filesystem clean flag now?",
      options: OPTIONS,
      working_directory: guarded
    });
    assert.equal(crossProcess.mode, "ASK_HUMAN");
    assert.equal(crossProcess.escalationReason, "recent_guard_escalation");

    // 5. Unrelated workspace is unaffected.
    const unrelated = await gemini.autopilotDecide({
      question: "Which test seam should we use?",
      options: OPTIONS,
      working_directory: other
    });
    assert.equal(unrelated.mode, "AUTOPILOT_PROCEED");

    // 6. An agent cannot lower the confidence floor to force a proceed.
    const lowered = await gemini.autopilotDecide({
      question: "[low] Which test seam should we use?",
      options: OPTIONS,
      min_confidence: 0.1,
      working_directory: other
    });
    assert.equal(lowered.mode, "ASK_HUMAN");
    assert.equal(lowered.escalationReason, "insufficient_confidence");
  } finally {
    for (const [key, value] of Object.entries(saved)) {
      if (value === undefined) delete process.env[key];
      else process.env[key] = value;
    }
    fs.rmSync(root, { recursive: true, force: true });
  }
});
