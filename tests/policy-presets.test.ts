import test from "node:test";
import assert from "node:assert/strict";
import {
  buildCommandGuardQuestions,
  buildDiffVerificationQuestions,
  buildContextPruneQuestions,
  buildBatchClassifyQuestions,
  buildTaskRouteQuestions
} from "../src/core/presets.js";
import {
  evaluateCommandGate,
  evaluateDiffGate,
  extractContextPruneResults
} from "../src/core/policy-engine.js";
import { collectGitContext } from "../src/core/git-collector.js";
import type { JevAnswer } from "../src/core/types.js";

test("evaluateCommandGate returns ALLOW for high-confidence safe commands and BLOCK for destructive ones", () => {
  const safeAnswers: Record<string, JevAnswer> = {
    is_safe_to_execute: { type: "noul", noul: 0.96 },
    is_destructive_or_irreversible: { type: "noul", noul: 0.02 },
    exposes_secrets_or_network_risk: { type: "noul", noul: 0.01 },
    blast_radius: { type: "score", score: 1.2, probabilities: { "1": 0.8, "2": 0.2 } },
    recommended_decision: {
      type: "choice",
      selected: "allow_silently",
      probabilities: { allow_silently: 0.95, ask_user_confirmation: 0.04, block_immediately: 0.01 }
    }
  };

  const allowDecision = evaluateCommandGate(safeAnswers);
  assert.equal(allowDecision.verdict, "ALLOW");
  assert.ok(allowDecision.confidence >= 0.9);

  const dangerousAnswers: Record<string, JevAnswer> = {
    is_safe_to_execute: { type: "noul", noul: 0.12 },
    is_destructive_or_irreversible: { type: "noul", noul: 0.91 },
    exposes_secrets_or_network_risk: { type: "noul", noul: 0.3 },
    blast_radius: { type: "score", score: 4.8, probabilities: { "5": 0.8, "4": 0.2 } },
    recommended_decision: {
      type: "choice",
      selected: "block_immediately",
      probabilities: { allow_silently: 0.01, ask_user_confirmation: 0.09, block_immediately: 0.9 }
    }
  };

  const blockDecision = evaluateCommandGate(dangerousAnswers);
  assert.equal(blockDecision.verdict, "BLOCK");
  assert.ok(blockDecision.reasons.length >= 2);
  assert.ok(blockDecision.remediation.length >= 1);
});

test("evaluateDiffGate enforces calibrated spec match, bug risk, and security thresholds", () => {
  const buggyDiffAnswers: Record<string, JevAnswer> = {
    fulfills_spec: { type: "noul", noul: 0.62 },
    introduces_bug_or_regression: { type: "noul", noul: 0.74 },
    has_security_risk: { type: "noul", noul: 0.1 },
    missing_tests_or_edge_cases: { type: "noul", noul: 0.81 },
    code_quality: { type: "score", score: 2.4, probabilities: { "2": 0.6, "3": 0.4 } },
    next_action: {
      type: "choice",
      selected: "fix_bugs",
      probabilities: {
        ready_to_commit: 0.05,
        fix_bugs: 0.75,
        add_tests: 0.15,
        address_security: 0.02,
        clarify_requirements: 0.03
      }
    }
  };

  const decision = evaluateDiffGate(buggyDiffAnswers);
  assert.equal(decision.verdict, "BLOCK");
  assert.ok(decision.remediation.some((r) => r.includes("spec") || r.includes("bug")));
});

test("buildContextPruneQuestions and extractContextPruneResults filter and rank candidates in parallel", () => {
  const candidates = [
    { id: "src/auth.ts", summary: "JWT token verification and session middleware" },
    { id: "src/theme.css", summary: "Button colors and typography variables" },
    { id: "src/db/users.ts", summary: "User repository and password hash lookup" }
  ];

  const questions = buildContextPruneQuestions("Fix JWT login expiration bug", candidates);
  assert.ok(questions.item_0);
  assert.ok(questions.item_1);
  assert.ok(questions.item_2);

  const mockAnswers: Record<string, JevAnswer> = {
    item_0: { type: "noul", noul: 0.95 },
    item_1: { type: "noul", noul: 0.08 },
    item_2: { type: "noul", noul: 0.78 }
  };

  const ranked = extractContextPruneResults(candidates, mockAnswers, 0.6);
  assert.equal(ranked.length, 2);
  assert.equal(ranked[0].item.id, "src/auth.ts");
  assert.equal(ranked[0].probability, 0.95);
  assert.equal(ranked[1].item.id, "src/db/users.ts");
});

test("Presets build valid question maps and GitCollector reads current git repo safely", () => {
  assert.ok(buildCommandGuardQuestions().is_safe_to_execute);
  assert.ok(buildDiffVerificationQuestions().fulfills_spec);
  assert.ok(buildTaskRouteQuestions().execution_strategy);

  const batchQ = buildBatchClassifyQuestions(
    ["Error: ECONNREFUSED", "Warning: unused var"],
    { bug: "Runtime error", lint: "Code style warning" },
    "Classify log line"
  );
  assert.equal(batchQ.item_0.type, "choice");
  assert.equal(batchQ.item_1.type, "choice");

  const gitCtx = collectGitContext(process.cwd());
  assert.equal(typeof gitCtx.isGitRepo, "boolean");
  assert.equal(gitCtx.isGitRepo, true);
});
