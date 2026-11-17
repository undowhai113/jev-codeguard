import type { GateVerdict, JevAnswer, PolicyDecision } from "./types.js";
import type { ContextCandidate } from "./presets.js";
import {
  isAutopilotEnabled,
  JEV_POLICY,
  type AutopilotThresholds,
  type CommandGateThresholds,
  type DiffGateThresholds
} from "./policy-config.js";

function getNoul(answers: Record<string, JevAnswer>, key: string, fallback = 0): number {
  const ans = answers[key];
  if (ans && ans.type === "noul" && typeof ans.noul === "number") {
    return ans.noul;
  }
  return fallback;
}

function getScore(answers: Record<string, JevAnswer>, key: string, fallback = 1): number {
  const ans = answers[key];
  if (ans && ans.type === "score" && typeof ans.score === "number") {
    if (ans.probabilities && "0" in ans.probabilities && !("5" in ans.probabilities)) {
      let weighted = 0;
      for (const [k, p] of Object.entries(ans.probabilities)) {
        const idx = Number(k);
        if (Number.isFinite(idx) && typeof p === "number") {
          weighted += (idx + 1) * p;
        }
      }
      return Number(Math.max(1, Math.min(5, weighted)).toFixed(2));
    }
    return ans.score;
  }
  return fallback;
}

function getChoice(answers: Record<string, JevAnswer>, key: string, fallback = ""): string {
  const ans = answers[key];
  if (ans && ans.type === "choice" && typeof ans.selected === "string") {
    return ans.selected;
  }
  return fallback;
}

const p2 = (value: number): string => value.toFixed(2);

function commandGateSummary(
  verdict: GateVerdict,
  pSafe: number,
  pDestructive: number,
  blastRadius: number
): string {
  return `[Jev Command Gate: ${verdict}] P(safe)=${p2(pSafe)} | P(destructive)=${p2(pDestructive)} | BlastRadius=${blastRadius.toFixed(1)}/5`;
}

/** Explains which ALLOW condition an ASK_USER command missed, using the same thresholds. */
function describeAllowGap(
  t: CommandGateThresholds,
  pSafe: number,
  pDestructive: number,
  pSecretRisk: number,
  blastRadius: number,
  recommended: string
): string {
  const gaps: string[] = [];
  if (blastRadius <= t.lowBlastMax) {
    if (pSafe < t.lowBlastSafeMin) gaps.push(`P(safe)=${p2(pSafe)} < ${t.lowBlastSafeMin}`);
    if (pDestructive > t.lowBlastRiskMax) gaps.push(`P(destructive)=${p2(pDestructive)} > ${t.lowBlastRiskMax}`);
    if (pSecretRisk > t.lowBlastRiskMax) gaps.push(`P(secret)=${p2(pSecretRisk)} > ${t.lowBlastRiskMax}`);
    return `low-blast action (blast ${blastRadius.toFixed(2)}/5) not auto-allowed: ${gaps.join(", ") || "standard band not met"}`;
  }
  if (blastRadius > t.allowBlastMax) gaps.push(`blast ${blastRadius.toFixed(2)}/5 > ${t.allowBlastMax}`);
  if (pSafe < t.allowSafeMin) gaps.push(`P(safe)=${p2(pSafe)} < ${t.allowSafeMin}`);
  if (pDestructive > t.allowDestructiveMax) gaps.push(`P(destructive)=${p2(pDestructive)} > ${t.allowDestructiveMax}`);
  if (pSecretRisk >= t.allowSecretRiskBelow) gaps.push(`P(secret)=${p2(pSecretRisk)} >= ${t.allowSecretRiskBelow}`);
  if (gaps.length === 0) {
    gaps.push(
      `model vote "${recommended}" (not allow_silently) and P(safe)=${p2(pSafe)} < ${t.strongAllowSafeMin} needed without that vote`
    );
  }
  return `blast ${blastRadius.toFixed(2)}/5 action not auto-allowed: ${gaps.join(", ")}`;
}

export function evaluateCommandGate(
  answers: Record<string, JevAnswer>,
  overrides: Partial<CommandGateThresholds> = {}
): PolicyDecision {
  const t: CommandGateThresholds = { ...JEV_POLICY.commandGate, ...overrides };
  const pSafe = getNoul(answers, "is_safe_to_execute", 0.5);
  const pDestructive = getNoul(answers, "is_destructive_or_irreversible", 0);
  const pSecretRisk = getNoul(answers, "exposes_secrets_or_network_risk", 0);
  const blastRadius = getScore(answers, "blast_radius", 2);
  const recommended = getChoice(answers, "recommended_decision", "ask_user_confirmation");
  const metrics = { pSafe, pDestructive, pSecretRisk, blastRadius, recommended };
  const confidence = Number(Math.max(pSafe, pDestructive, pSecretRisk).toFixed(3));

  // Every BLOCK trigger pushes its own reason, so a BLOCK is never reason-less.
  const blockReasons: string[] = [];
  const remediation: string[] = [];

  if (pDestructive >= t.blockDestructiveMin) {
    blockReasons.push(
      `High probability of destructive/irreversible impact: P(destructive)=${p2(pDestructive)} >= ${t.blockDestructiveMin}`
    );
    remediation.push(
      "Use a non-destructive alternative (e.g., dry-run flag, targeted file path, or git stash instead of hard reset/clean)."
    );
  }
  if (pSecretRisk >= t.blockSecretRiskMin) {
    blockReasons.push(
      `Elevated secret exposure or network risk: P(secret_or_net_risk)=${p2(pSecretRisk)} >= ${t.blockSecretRiskMin}`
    );
    remediation.push(
      "Remove any credentials/tokens from command arguments and avoid piping remote scripts directly to a shell."
    );
  }
  const concreteRisk = Math.max(pDestructive, pSecretRisk);
  if (pSafe < t.blockUnsafeSafeMax && concreteRisk > t.blockUnsafeRiskMin) {
    blockReasons.push(
      `Low calibrated safety with concrete risk: P(safe)=${p2(pSafe)} < ${t.blockUnsafeSafeMax} and max(P(destructive), P(secret))=${p2(concreteRisk)} > ${t.blockUnsafeRiskMin}`
    );
  }
  if (recommended === "block_immediately" && pDestructive >= t.blockModelVoteDestructiveMin) {
    blockReasons.push(
      `Model recommends block_immediately with P(destructive)=${p2(pDestructive)} >= ${t.blockModelVoteDestructiveMin}`
    );
  }

  if (blockReasons.length > 0) {
    if (remediation.length === 0) {
      remediation.push(
        "Narrow the scope of the command or ask the user explicitly before running destructive operations."
      );
    }
    return {
      verdict: "BLOCK",
      confidence,
      summary: commandGateSummary("BLOCK", pSafe, pDestructive, blastRadius),
      reasons: blockReasons,
      remediation,
      metrics
    };
  }

  const standardBand =
    pSafe >= t.allowSafeMin &&
    pDestructive <= t.allowDestructiveMax &&
    pSecretRisk < t.allowSecretRiskBelow &&
    blastRadius <= t.allowBlastMax;
  const strongEvidence =
    pSafe >= t.strongAllowSafeMin &&
    pDestructive <= t.strongAllowRiskMax &&
    pSecretRisk <= t.strongAllowRiskMax;
  const lowBlastBand =
    blastRadius <= t.lowBlastMax &&
    pSafe >= t.lowBlastSafeMin &&
    pDestructive <= t.lowBlastRiskMax &&
    pSecretRisk <= t.lowBlastRiskMax;

  let allowBand: string | null = null;
  if (standardBand && recommended === "allow_silently") allowBand = "standard band + allow_silently vote";
  else if (standardBand && strongEvidence) allowBand = "strong-evidence band";
  else if (lowBlastBand) allowBand = "low-blast band";

  if (allowBand) {
    return {
      verdict: "ALLOW",
      confidence,
      summary: commandGateSummary("ALLOW", pSafe, pDestructive, blastRadius),
      reasons: [
        `Calibrated safety check passed (${allowBand}): P(safe)=${p2(pSafe)}, P(destructive)=${p2(pDestructive)}, P(secret)=${p2(pSecretRisk)}, blast_radius=${blastRadius.toFixed(2)}`
      ],
      remediation: [],
      metrics
    };
  }

  return {
    verdict: "ASK_USER",
    confidence,
    summary: commandGateSummary("ASK_USER", pSafe, pDestructive, blastRadius),
    reasons: [
      `Human confirmation advised — ${describeAllowGap(t, pSafe, pDestructive, pSecretRisk, blastRadius, recommended)}.`
    ],
    remediation: ["Request user confirmation before executing this action."],
    metrics
  };
}

/**
 * Decision for a guard request whose `exact_command` is not a literal command line.
 * Scoring prose is meaningless (agents described "read-only" intent instead of the
 * command they then ran), so the gate refuses to auto-allow it.
 */
export function buildUnverifiableCommandDecision(signals: string[]): PolicyDecision {
  return {
    verdict: "ASK_USER",
    confidence: 0,
    summary: "[Jev Command Gate: ASK_USER] exact_command is not a literal command line",
    reasons: [
      `exact_command looks like a prose description, not the command that will run (signals: ${signals.join(", ") || "unknown"}).`
    ],
    remediation: [
      "Re-call jev_guard_action with exact_command set to the verbatim command line you will execute (program + arguments); put the explanation in context.",
      "If the action cannot be expressed as one literal command, ask the user to confirm it."
    ],
    metrics: { commandShape: "prose", signals: signals.join(",") }
  };
}

export function evaluateDiffGate(
  answers: Record<string, JevAnswer>,
  overrides: Partial<DiffGateThresholds> = {},
  options: { isDocsOnlyDiff?: boolean } = {}
): PolicyDecision {
  const t: DiffGateThresholds = { ...JEV_POLICY.diffGate, ...overrides };
  const pFulfillsSpec = getNoul(answers, "fulfills_spec", 0.5);
  const pBugRisk = getNoul(answers, "introduces_bug_or_regression", 0);
  const pSecurityRisk = getNoul(answers, "has_security_risk", 0);
  const pMissingTests = getNoul(answers, "missing_tests_or_edge_cases", 0);
  const codeQuality = getScore(answers, "code_quality", 3);
  const nextAction = getChoice(answers, "next_action", "ready_to_commit");

  // Only concrete security/regression risk blocks. Spec mismatch and missing tests are
  // warnings: 62% of real verify calls used to BLOCK on spec alone, agents then rewrote
  // the spec until it passed or ignored the gate.
  const blockers: string[] = [];
  const warnings: string[] = [];
  const remediation: string[] = [];

  if (pSecurityRisk >= t.blockSecurityRiskMin) {
    blockers.push(
      `[BLOCKER] Security risk in added code: P(security_risk)=${p2(pSecurityRisk)} >= ${t.blockSecurityRiskMin}`
    );
    remediation.push(
      "Run `jev_audit_code` on the changed files to pinpoint the exact security vector and apply the local skill remediation."
    );
  }

  if (pBugRisk >= t.blockBugRiskMin) {
    blockers.push(
      `[BLOCKER] Bug or regression risk is elevated: P(bug_risk)=${p2(pBugRisk)} >= ${t.blockBugRiskMin}`
    );
    remediation.push("Inspect changed logic for unhandled edge cases, broken imports, or regressions.");
  }

  const isCleanDocsCheckpoint =
    Boolean(options.isDocsOnlyDiff) &&
    pBugRisk < t.docsCheckpointRiskBelow &&
    pSecurityRisk < t.docsCheckpointRiskBelow &&
    (codeQuality >= t.docsCheckpointQualityMin ||
      (pBugRisk <= t.docsCheckpointNegligibleRisk && pSecurityRisk <= t.docsCheckpointNegligibleRisk));

  if (!isCleanDocsCheckpoint && pFulfillsSpec < t.minSpecMatch) {
    warnings.push(
      `[WARNING] Spec alignment uncertain: P(fulfills_spec)=${p2(pFulfillsSpec)} < ${t.minSpecMatch}`
    );
    remediation.push(
      "Compare the diff with the user's original request (not a paraphrase of the diff). If a requirement looks unmet or the diff mixes in other uncommitted work, tell the user which parts are uncertain and confirm scope; do not rewrite the spec just to pass the gate."
    );
  }

  if (!isCleanDocsCheckpoint && (pMissingTests >= t.missingTestsWarnMin || nextAction === "add_tests")) {
    warnings.push(
      `[WARNING] Test coverage likely missing: P(missing_tests)=${p2(pMissingTests)}${nextAction === "add_tests" ? " (model next_action=add_tests)" : ""}`
    );
    remediation.push("Add unit or integration tests covering the modified code paths.");
  }

  const verdict: GateVerdict = blockers.length > 0 ? "BLOCK" : warnings.length > 0 ? "ASK_USER" : "ALLOW";
  const reasons = [...blockers, ...warnings];
  if (reasons.length === 0) {
    reasons.push(
      `Diff verified cleanly: P(fulfills_spec)=${p2(pFulfillsSpec)}, P(bug)=${p2(pBugRisk)}, quality=${codeQuality.toFixed(1)}/5`
    );
  }

  return {
    verdict,
    confidence: Number(pFulfillsSpec.toFixed(3)),
    summary: `[Jev Diff Gate: ${verdict}] P(spec)=${p2(pFulfillsSpec)} | P(bug)=${p2(pBugRisk)} | P(sec)=${p2(pSecurityRisk)} | Quality=${codeQuality.toFixed(1)}/5 | Next=${nextAction}`,
    reasons,
    remediation,
    metrics: {
      pFulfillsSpec,
      pBugRisk,
      pSecurityRisk,
      pMissingTests,
      codeQuality,
      nextAction
    }
  };
}

export interface RankedContextItem {
  item: ContextCandidate;
  probability: number;
}

export function extractContextPruneResults(
  candidates: ContextCandidate[],
  answers: Record<string, JevAnswer>,
  threshold = 0.60
): RankedContextItem[] {
  const results: RankedContextItem[] = [];
  const bounded = candidates.slice(0, 100);
  for (let i = 0; i < bounded.length; i += 1) {
    const prob = getNoul(answers, `item_${i}`, 0);
    if (prob >= threshold) {
      results.push({
        item: bounded[i],
        probability: prob
      });
    }
  }
  results.sort((a, b) => b.probability - a.probability);
  return results;
}

/** A recent jev_guard_action verdict that requires a real human decision. */
export interface GuardEscalation {
  timestamp: string;
  verdict: "ASK_USER" | "BLOCK";
  command: string;
  workspace: string;
  workspacePath?: string;
  agent?: string;
}

function normalizeWorkspacePath(value: string): string {
  return value.replace(/\\/g, "/").replace(/\/+$/, "").toLowerCase();
}

/**
 * Finds the newest guard escalation that an autopilot decision must not override.
 * "Related" means the same workspace (path or name) inside the window. In the real
 * logs every autopilot call made within 15 minutes of a guard ASK_USER in the same
 * workspace was the agent asking whether it could skip that confirmation. When the
 * workspace cannot be identified (IDE host directory), any escalation in the window
 * counts — failing towards asking the human.
 */
export function findBlockingGuardEscalation(
  escalations: GuardEscalation[],
  target: {
    workspaceName: string;
    workspacePath?: string;
    now?: Date;
    windowMs?: number;
    workspaceIsUnknown?: boolean;
  }
): GuardEscalation | undefined {
  const now = (target.now ?? new Date()).getTime();
  const windowMs = target.windowMs ?? JEV_POLICY.autopilot.guardEscalationWindowMs;
  const targetPath = target.workspacePath ? normalizeWorkspacePath(target.workspacePath) : "";
  const targetName = target.workspaceName.trim().toLowerCase();

  let newest: GuardEscalation | undefined;
  let newestTime = -Infinity;
  for (const esc of escalations) {
    if (esc.verdict !== "ASK_USER" && esc.verdict !== "BLOCK") continue;
    const at = Date.parse(esc.timestamp);
    if (!Number.isFinite(at)) continue;
    const age = now - at;
    if (age < 0 || age > windowMs) continue;
    const samePath =
      targetPath.length > 0 &&
      typeof esc.workspacePath === "string" &&
      normalizeWorkspacePath(esc.workspacePath) === targetPath;
    const sameName = targetName.length > 0 && esc.workspace.trim().toLowerCase() === targetName;
    if (!(target.workspaceIsUnknown || samePath || sameName)) continue;
    if (at > newestTime) {
      newest = esc;
      newestTime = at;
    }
  }
  return newest;
}

export type AutopilotEscalationReason =
  | "autopilot_disabled"
  | "recent_guard_escalation"
  | "insufficient_confidence";

export interface AutopilotProxyVerdict {
  mode: "AUTOPILOT_PROCEED" | "ASK_HUMAN";
  selectedOption: string;
  selectedProbability: number;
  allProbabilities: Record<string, number>;
  isReversible: number;
  requiresHuman: number;
  alignmentScore: number;
  agentDirective: string;
  /** Why the decision went to the human (absent when autopilot proceeds). */
  escalationReason?: AutopilotEscalationReason;
  /** The guard verdict that forced ASK_HUMAN, when escalationReason is recent_guard_escalation. */
  guardEscalation?: GuardEscalation;
}

export interface AutopilotGateContext {
  /** Autopilot may only proceed when explicitly enabled (JEV_AUTOPILOT=1). */
  enabled: boolean;
  /** Newest related guard ASK_USER/BLOCK; when present the human must decide. */
  guardEscalation?: GuardEscalation;
  now?: Date;
}

function describeGuardEscalation(esc: GuardEscalation, now: Date): string {
  const ageMs = now.getTime() - Date.parse(esc.timestamp);
  const ageMin = Number.isFinite(ageMs) ? Math.max(0, Math.round(ageMs / 60000)) : 0;
  const command = esc.command.length > 160 ? `${esc.command.slice(0, 157)}...` : esc.command;
  return `jev_guard_action returned ${esc.verdict} for \`${command}\` in workspace ${esc.workspace} ${ageMin} min ago`;
}

function recommendationClause(selectedOption: string, selectedProbability: number): string {
  return selectedOption
    ? `recommend "${selectedOption}" as the first option (P=${p2(selectedProbability)})`
    : "Jev returned no recommended option";
}

export function evaluateAutopilotProxy(
  answers: Record<string, JevAnswer>,
  overrides: Partial<AutopilotThresholds> = {},
  gate: AutopilotGateContext = { enabled: isAutopilotEnabled() }
): AutopilotProxyVerdict {
  const t: AutopilotThresholds = { ...JEV_POLICY.autopilot, ...overrides };
  const choiceAns = answers.selected_option;
  const selectedOption =
    choiceAns && choiceAns.type === "choice" ? choiceAns.selected : "";
  const allProbabilities =
    choiceAns && choiceAns.type === "choice" ? choiceAns.probabilities : {};
  const selectedProbability =
    selectedOption && typeof allProbabilities[selectedOption] === "number"
      ? allProbabilities[selectedOption]
      : 0;

  const isReversible = getNoul(answers, "is_reversible_technical_choice", 0.5);
  const requiresHuman = getNoul(
    answers,
    "requires_private_business_or_human_taste",
    0.5
  );
  const alignmentScore = getScore(answers, "alignment_strength", 3);
  const base = {
    selectedOption,
    selectedProbability,
    allProbabilities,
    isReversible,
    requiresHuman,
    alignmentScore
  };
  const recommendation = recommendationClause(selectedOption, selectedProbability);
  const esc = gate.guardEscalation;
  const guardNote = esc ? describeGuardEscalation(esc, gate.now ?? new Date()) : "";

  if (!gate.enabled) {
    return {
      ...base,
      mode: "ASK_HUMAN",
      escalationReason: "autopilot_disabled",
      ...(esc ? { guardEscalation: esc } : {}),
      agentDirective: `[JEV AUTOPILOT OFF]: Autopilot is disabled (set JEV_AUTOPILOT=1 to enable). Ask the user and ${recommendation}.${guardNote ? ` Also confirm: ${guardNote}.` : ""}`
    };
  }

  if (esc) {
    return {
      ...base,
      mode: "ASK_HUMAN",
      escalationReason: "recent_guard_escalation",
      guardEscalation: esc,
      agentDirective: `[JEV ESCALATE TO HUMAN]: ${guardNote}. Autopilot cannot replace that confirmation; ask the user explicitly and ${recommendation}.`
    };
  }

  const canAutopilot =
    selectedOption.length > 0 &&
    selectedProbability >= t.minChoiceProbability &&
    isReversible >= t.minReversibleProbability &&
    requiresHuman < t.requiresHumanBelow &&
    (alignmentScore >= t.minAlignmentScore || selectedProbability >= t.strongChoiceProbability);

  if (canAutopilot) {
    return {
      ...base,
      mode: "AUTOPILOT_PROCEED",
      agentDirective: `[JEV AUTOPILOT]: Option "${selectedOption}" clears the autopilot bar for a reversible technical choice (P=${p2(selectedProbability)}, reversible=${p2(isReversible)}, alignment=${alignmentScore.toFixed(1)}/5). You may proceed with it; state the choice in one line and ask the user if new risk, cost, or scope appears.`
    };
  }

  return {
    ...base,
    mode: "ASK_HUMAN",
    escalationReason: "insufficient_confidence",
    agentDirective: `[JEV ESCALATE TO HUMAN]: This decision requires human input (P(requires_human)=${p2(requiresHuman)}, top_choice="${selectedOption}" at P=${p2(selectedProbability)}). Ask the user and ${recommendation}.`
  };
}
