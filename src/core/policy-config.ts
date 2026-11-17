/**
 * Single source of truth for every calibrated gate threshold used by MCP-Jev.
 *
 * Values were re-calibrated against 339 real events (Codex + Antigravity,
 * 2026-10-25 → 2026-11-05). Keep numbers here — gate functions must not embed
 * their own literals, so a BLOCK trigger and the reason it reports can never
 * drift apart again.
 */

export interface CommandGateThresholds {
  /** BLOCK when P(destructive_or_irreversible) >= this. */
  blockDestructiveMin: number;
  /** BLOCK when P(exposes_secrets_or_network_risk) >= this. */
  blockSecretRiskMin: number;
  /** BLOCK when P(safe) < this AND (P(destructive) or P(secret)) > blockUnsafeRiskMin. */
  blockUnsafeSafeMax: number;
  blockUnsafeRiskMin: number;
  /** BLOCK when the model votes `block_immediately` AND P(destructive) >= this. */
  blockModelVoteDestructiveMin: number;

  /** Standard ALLOW band; also needs `allow_silently` or the strong-evidence band. */
  allowSafeMin: number;
  allowDestructiveMax: number;
  /** Strict upper bound (P(secret) must be < this). */
  allowSecretRiskBelow: number;
  allowBlastMax: number;

  /** Strong-evidence ALLOW that does not need the model's `allow_silently` vote. */
  strongAllowSafeMin: number;
  strongAllowRiskMax: number;

  /**
   * Low-blast-radius ALLOW (read-only inspection, local tests). P(safe) floor was
   * 0.54, which let a raw-volume read (P=0.59) and an SSH infra survey (P=0.54)
   * through as ALLOW; 0.70 sends those to ASK_USER.
   */
  lowBlastMax: number;
  lowBlastSafeMin: number;
  lowBlastRiskMax: number;
}

export interface DiffGateThresholds {
  /**
   * Below this P(fulfills_spec) the diff gets a WARNING (ASK_USER), never a BLOCK.
   * 0.68 has been live since 2026-11-01; kept so before/after logs stay comparable.
   */
  minSpecMatch: number;
  /** BLOCK when P(introduces_bug_or_regression) >= this. */
  blockBugRiskMin: number;
  /** BLOCK when P(has_security_risk) >= this. */
  blockSecurityRiskMin: number;
  /** WARNING when P(missing_tests_or_edge_cases) >= this. */
  missingTestsWarnMin: number;
  /** Docs-only checkpoint skips spec/test warnings when both risks are below this... */
  docsCheckpointRiskBelow: number;
  /** ...and quality is at least this, or both risks are at most docsCheckpointNegligibleRisk. */
  docsCheckpointQualityMin: number;
  docsCheckpointNegligibleRisk: number;
}

export interface AutopilotThresholds {
  /** Minimum probability of the selected option. Callers may raise it, never lower it. */
  minChoiceProbability: number;
  minReversibleProbability: number;
  /** Strict upper bound for P(requires_private_business_or_human_taste). */
  requiresHumanBelow: number;
  minAlignmentScore: number;
  /** A very confident choice may proceed with a weaker alignment score. */
  strongChoiceProbability: number;
  /** A guard ASK_USER/BLOCK in the same workspace within this window forces ASK_HUMAN. */
  guardEscalationWindowMs: number;
}

export interface AuditGateThresholds {
  /** A vector is reported as violated when its probability >= this. */
  violationThreshold: number;
  /** BLOCK when a security vector is violated and the overall score is below this. */
  blockScoreBelow: number;
  /** BLOCK when the model votes `block_and_fix` and the overall score is below this. */
  blockModelVoteScoreBelow: number;
  /** Non-test files: BLOCK when score < blockStrongVectorScoreBelow and a vector >= blockStrongVectorMin. */
  blockStrongVectorMin: number;
  blockStrongVectorScoreBelow: number;
  /** Any file (tests included): BLOCK when a security vector >= this. */
  blockCriticalVectorMin: number;
  /** Non-test files: ASK_USER when score < askScoreBelow and a security vector >= askVectorMin. */
  askVectorMin: number;
  askScoreBelow: number;
  /**
   * No vector crossed the threshold but the overall score is below this (or the model
   * voted `block_and_fix`): ASK_USER for manual review instead of claiming "all passed".
   */
  lowScoreReviewBelow: number;
}

export interface JevPolicy {
  commandGate: CommandGateThresholds;
  diffGate: DiffGateThresholds;
  autopilot: AutopilotThresholds;
  audit: AuditGateThresholds;
}

export const JEV_POLICY: Readonly<JevPolicy> = Object.freeze({
  commandGate: Object.freeze({
    blockDestructiveMin: 0.65,
    blockSecretRiskMin: 0.55,
    blockUnsafeSafeMax: 0.25,
    blockUnsafeRiskMin: 0.15,
    blockModelVoteDestructiveMin: 0.4,
    allowSafeMin: 0.72,
    allowDestructiveMax: 0.18,
    allowSecretRiskBelow: 0.2,
    allowBlastMax: 3.1,
    strongAllowSafeMin: 0.8,
    strongAllowRiskMax: 0.1,
    lowBlastMax: 2.0,
    lowBlastSafeMin: 0.7,
    lowBlastRiskMax: 0.1
  }),
  diffGate: Object.freeze({
    minSpecMatch: 0.68,
    blockBugRiskMin: 0.45,
    blockSecurityRiskMin: 0.5,
    missingTestsWarnMin: 0.65,
    docsCheckpointRiskBelow: 0.15,
    docsCheckpointQualityMin: 3.3,
    docsCheckpointNegligibleRisk: 0.05
  }),
  autopilot: Object.freeze({
    minChoiceProbability: 0.65,
    minReversibleProbability: 0.55,
    requiresHumanBelow: 0.45,
    minAlignmentScore: 2.5,
    strongChoiceProbability: 0.75,
    guardEscalationWindowMs: 15 * 60 * 1000
  }),
  audit: Object.freeze({
    violationThreshold: 0.55,
    blockScoreBelow: 2.5,
    blockModelVoteScoreBelow: 3.15,
    blockStrongVectorMin: 0.7,
    blockStrongVectorScoreBelow: 3.65,
    blockCriticalVectorMin: 0.82,
    askVectorMin: 0.62,
    askScoreBelow: 3.65,
    lowScoreReviewBelow: 3.0
  })
});

/** Autopilot is opt-in: it only auto-proceeds when JEV_AUTOPILOT=1 (or "true"). */
export function isAutopilotEnabled(env: NodeJS.ProcessEnv = process.env): boolean {
  const raw = (env.JEV_AUTOPILOT ?? "").trim().toLowerCase();
  return raw === "1" || raw === "true";
}
