import test from "node:test";
import assert from "node:assert/strict";
import {
  evaluateAutopilotProxy,
  evaluateCommandGate,
  evaluateDiffGate,
  findBlockingGuardEscalation,
  type GuardEscalation
} from "../src/core/policy-engine.js";
import { isAutopilotEnabled, JEV_POLICY } from "../src/core/policy-config.js";
import type { JevAnswer } from "../src/core/types.js";

// Probabilities below are taken from real events in events-snapshot.jsonl (#index noted).

function guardAnswers(
  pSafe: number,
  pDestructive: number,
  pSecret: number,
  blast: number,
  recommended = "ask_user_confirmation"
): Record<string, JevAnswer> {
  return {
    is_safe_to_execute: { type: "noul", noul: pSafe },
    is_destructive_or_irreversible: { type: "noul", noul: pDestructive },
    exposes_secrets_or_network_risk: { type: "noul", noul: pSecret },
    blast_radius: { type: "score", score: blast, probabilities: {} },
    recommended_decision: {
      type: "choice",
      selected: recommended,
      probabilities: { [recommended]: 0.9 }
    }
  };
}

function diffAnswers(
  spec: number,
  bug: number,
  sec: number,
  opts: { missingTests?: number; quality?: number; next?: string } = {}
): Record<string, JevAnswer> {
  const next = opts.next ?? "ready_to_commit";
  return {
    fulfills_spec: { type: "noul", noul: spec },
    introduces_bug_or_regression: { type: "noul", noul: bug },
    has_security_risk: { type: "noul", noul: sec },
    missing_tests_or_edge_cases: { type: "noul", noul: opts.missingTests ?? 0.1 },
    code_quality: { type: "score", score: opts.quality ?? 3.8, probabilities: {} },
    next_action: { type: "choice", selected: next, probabilities: { [next]: 0.8 } }
  };
}

test("command gate: low-blast ALLOW now needs P(safe) >= 0.70 (real #323/#329 become ASK_USER)", () => {
  // #323 read-only SSH survey of the Proxmox host, #329 raw read of exFAT boot sectors.
  for (const [pSafe, blast] of [
    [0.54, 1.04],
    [0.59, 1.18]
  ]) {
    const decision = evaluateCommandGate(guardAnswers(pSafe, 0.08, 0.07, blast));
    assert.equal(decision.verdict, "ASK_USER", `P(safe)=${pSafe} must not be auto-allowed`);
    assert.match(decision.reasons[0], new RegExp(`P\\(safe\\)=${pSafe.toFixed(2)} < 0\\.7`));
  }
  // #156 read-only git fetch into review refs stays ALLOW.
  assert.equal(evaluateCommandGate(guardAnswers(0.72, 0.07, 0.08, 1.33)).verdict, "ALLOW");
  // Standard band with an allow_silently vote (local docs commit) stays ALLOW.
  assert.equal(
    evaluateCommandGate(guardAnswers(0.78, 0.06, 0.03, 2.99, "allow_silently")).verdict,
    "ALLOW"
  );
});

test("command gate: every BLOCK trigger reports its own reason (no reason-less BLOCK)", () => {
  const cases: Array<{ answers: Record<string, JevAnswer>; mustMention: RegExp }> = [
    // Old code blocked at >= 0.65 but only explained >= 0.70.
    { answers: guardAnswers(0.6, 0.67, 0.05, 3), mustMention: /P\(destructive\)=0\.67 >= 0\.65/ },
    // Old code blocked at >= 0.55 but only explained >= 0.60.
    { answers: guardAnswers(0.6, 0.05, 0.57, 3), mustMention: /P\(secret_or_net_risk\)=0\.57 >= 0\.55/ },
    { answers: guardAnswers(0.2, 0.2, 0.05, 3), mustMention: /P\(safe\)=0\.20 < 0\.25/ },
    {
      answers: guardAnswers(0.5, 0.45, 0.05, 3, "block_immediately"),
      mustMention: /block_immediately with P\(destructive\)=0\.45 >= 0\.4/
    }
  ];
  for (const { answers, mustMention } of cases) {
    const decision = evaluateCommandGate(answers);
    assert.equal(decision.verdict, "BLOCK");
    assert.ok(decision.reasons.length >= 1, "BLOCK must carry at least one reason");
    assert.ok(decision.reasons.some((r) => mustMention.test(r)), `missing reason ${mustMention}`);
    assert.ok(decision.remediation.length >= 1);
  }
  // #0: P(safe)=0.23 but no concrete destructive/secret risk -> human decides, not BLOCK.
  assert.equal(evaluateCommandGate(guardAnswers(0.23, 0.04, 0.1, 3.4)).verdict, "ASK_USER");
});

test("command gate: thresholds come from the named JEV_POLICY config and can be overridden", () => {
  assert.equal(JEV_POLICY.commandGate.lowBlastSafeMin, 0.7);
  assert.ok(Object.isFrozen(JEV_POLICY.commandGate));
  const answers = guardAnswers(0.54, 0.08, 0.07, 1.04);
  assert.equal(evaluateCommandGate(answers).verdict, "ASK_USER");
  assert.equal(evaluateCommandGate(answers, { lowBlastSafeMin: 0.5 }).verdict, "ALLOW");
});

test("diff gate: spec mismatch alone is a warning (ASK_USER), never a BLOCK", () => {
  // #322 Codex review of a PR: spec 0.34, bug 0.04, sec 0.04 used to BLOCK.
  const decision = evaluateDiffGate(diffAnswers(0.34, 0.04, 0.04));
  assert.equal(decision.verdict, "ASK_USER");
  assert.match(decision.reasons[0], /^\[WARNING\] Spec alignment uncertain: P\(fulfills_spec\)=0\.34 < 0\.68/);
  assert.ok(decision.remediation.some((r) => /do not rewrite the spec/i.test(r)));
  // Spec just at the threshold with low risk is clean.
  assert.equal(evaluateDiffGate(diffAnswers(0.68, 0.2, 0.15)).verdict, "ALLOW");
});

test("diff gate: only elevated regression or security risk blocks", () => {
  // #138 bug 0.74 -> BLOCK, and the spec warning is still listed.
  const bug = evaluateDiffGate(diffAnswers(0.47, 0.74, 0.28));
  assert.equal(bug.verdict, "BLOCK");
  assert.ok(bug.reasons.some((r) => r.startsWith("[BLOCKER] Bug or regression")));
  assert.ok(bug.reasons.some((r) => r.startsWith("[WARNING] Spec alignment")));
  // #226 security 0.56 with spec 0.70 -> BLOCK on security alone.
  const sec = evaluateDiffGate(diffAnswers(0.7, 0.41, 0.56));
  assert.equal(sec.verdict, "BLOCK");
  assert.deepEqual(
    sec.reasons.filter((r) => r.startsWith("[BLOCKER]")).length,
    1
  );
  // Missing tests stays a warning.
  const tests = evaluateDiffGate(diffAnswers(0.93, 0.14, 0.15, { missingTests: 0.8 }));
  assert.equal(tests.verdict, "ASK_USER");
  assert.match(tests.reasons[0], /^\[WARNING\] Test coverage likely missing/);
});

test("diff gate: clean docs-only checkpoints pass even with a low spec score", () => {
  const decision = evaluateDiffGate(diffAnswers(0.3, 0.03, 0.03, { quality: 3.5 }), {}, {
    isDocsOnlyDiff: true
  });
  assert.equal(decision.verdict, "ALLOW");
  assert.ok(JEV_POLICY.diffGate.minSpecMatch >= 0.65 && JEV_POLICY.diffGate.minSpecMatch <= 0.7);
});

function autopilotAnswers(selectedP: number): Record<string, JevAnswer> {
  return {
    selected_option: {
      type: "choice",
      selected: "A",
      probabilities: { A: selectedP, B: Number((1 - selectedP).toFixed(2)) }
    },
    is_reversible_technical_choice: { type: "noul", noul: 0.9 },
    requires_private_business_or_human_taste: { type: "noul", noul: 0.1 },
    alignment_strength: { type: "score", score: 4.6, probabilities: {} }
  };
}

test("autopilot is off unless JEV_AUTOPILOT=1 and never tells the agent not to interrupt", () => {
  assert.equal(isAutopilotEnabled({}), false);
  assert.equal(isAutopilotEnabled({ JEV_AUTOPILOT: "0" }), false);
  assert.equal(isAutopilotEnabled({ JEV_AUTOPILOT: "1" }), true);

  const off = evaluateAutopilotProxy(autopilotAnswers(0.97), {}, { enabled: false });
  assert.equal(off.mode, "ASK_HUMAN");
  assert.equal(off.escalationReason, "autopilot_disabled");
  assert.match(off.agentDirective, /JEV_AUTOPILOT=1/);
  assert.match(off.agentDirective, /recommend "A"/);

  const on = evaluateAutopilotProxy(autopilotAnswers(0.97), {}, { enabled: true });
  assert.equal(on.mode, "AUTOPILOT_PROCEED");
  assert.equal(on.escalationReason, undefined);
  assert.doesNotMatch(on.agentDirective, /not interrupt/i);

  const weak = evaluateAutopilotProxy(autopilotAnswers(0.6), {}, { enabled: true });
  assert.equal(weak.mode, "ASK_HUMAN");
  assert.equal(weak.escalationReason, "insufficient_confidence");
});

test("autopilot cannot proceed after a related guard ASK_USER/BLOCK within 15 minutes", () => {
  const now = new Date("2026-11-05T02:33:00Z");
  const escalation: GuardEscalation = {
    timestamp: "2026-11-05T02:32:00Z",
    verdict: "ASK_USER",
    command: "chkdsk.exe E: /markclean",
    workspace: "acme-cloud",
    workspacePath: "D:\\Workspaces\\acme-cloud"
  };
  const verdict = evaluateAutopilotProxy(autopilotAnswers(1), {}, {
    enabled: true,
    guardEscalation: escalation,
    now
  });
  assert.equal(verdict.mode, "ASK_HUMAN");
  assert.equal(verdict.escalationReason, "recent_guard_escalation");
  assert.match(verdict.agentDirective, /chkdsk\.exe E: \/markclean/);
  assert.match(verdict.agentDirective, /1 min ago/);
});

test("findBlockingGuardEscalation matches workspace and window, failing towards the human", () => {
  const now = new Date("2026-11-05T03:00:00Z");
  const at = (minutesAgo: number) => new Date(now.getTime() - minutesAgo * 60000).toISOString();
  const escalations: GuardEscalation[] = [
    { timestamp: at(16), verdict: "BLOCK", command: "old", workspace: "acme-cloud", workspacePath: "D:\\Workspaces\\acme-cloud" },
    { timestamp: at(5), verdict: "ASK_USER", command: "gh pr merge 50 --admin", workspace: "acme-sec-portal", workspacePath: "D:\\Workspaces\\acme-sec-portal" },
    { timestamp: at(3), verdict: "BLOCK", command: "rm -rf build", workspace: "acme-cloud", workspacePath: "d:\\Workspaces\\acme-cloud\\" }
  ];

  // Case-insensitive Windows path match, newest wins, the 16-minute-old one is ignored.
  assert.equal(
    findBlockingGuardEscalation(escalations, { workspaceName: "acme-cloud", workspacePath: "D:\\Workspaces\\acme-cloud", now })?.command,
    "rm -rf build"
  );
  assert.equal(
    findBlockingGuardEscalation(escalations, { workspaceName: "other", workspacePath: "D:\\other", now }),
    undefined
  );
  assert.equal(
    findBlockingGuardEscalation(escalations, {
      workspaceName: "acme-cloud",
      workspacePath: "D:\\Workspaces\\acme-cloud",
      now: new Date(now.getTime() + 13 * 60000)
    }),
    undefined
  );
  // Unknown workspace (IDE host dir): any escalation in the window counts.
  assert.equal(
    findBlockingGuardEscalation(escalations, {
      workspaceName: "Antigravity",
      workspacePath: "C:\\Users\\Developer\\AppData\\Local\\Programs\\Antigravity",
      workspaceIsUnknown: true,
      now
    })?.command,
    "rm -rf build"
  );
  assert.equal(JEV_POLICY.autopilot.guardEscalationWindowMs, 15 * 60 * 1000);
});
