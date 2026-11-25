import fs from "node:fs";
import path from "node:path";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import { JevClient } from "../core/jev-client.js";
import {
  buildAutopilotProxyQuestions,
  buildBatchClassifyQuestions,
  buildCommandGuardQuestions,
  buildContextPruneQuestions,
  buildDiffVerificationQuestions,
  buildTaskRouteQuestions,
  DEFAULT_DEVELOPER_PROFILE,
  type ContextCandidate
} from "../core/presets.js";
import {
  buildUnverifiableCommandDecision,
  evaluateAutopilotProxy,
  evaluateCommandGate,
  evaluateDiffGate,
  extractContextPruneResults,
  findBlockingGuardEscalation,
  type GuardEscalation
} from "../core/policy-engine.js";
import { isAutopilotEnabled, JEV_POLICY } from "../core/policy-config.js";
import { assessCommandShape } from "../core/command-shape.js";
import { budgetMultiFileDiff, collectGitContext } from "../core/git-collector.js";
import {
  buildProjectContextEnvelope,
  buildSpecRequirementMatrix,
  extractCompanionTestsContext,
  extractCrossFileContracts,
  extractFileHeaderContext,
  extractPostEditHunkScopes,
  extractReferencedDocsAndFiles,
  extractReverseDependents,
  extractStructuralDiffMap,
  isGenericHostDirectory,
  isSensitiveFilePath,
  isWithinWorkspaceBoundary,
  resolveTargetWorkspace,
  runFastSyntaxProbe
} from "../core/context-enricher.js";
import { auditCodeWithSkills } from "../core/skill-auditor.js";
import {
  extractHybridAstSkeletons,
  queryCodeGraphIntelligence,
  runHybridStaticAnalysis
} from "../core/hybrid-ast-engine.js";
import { readSessionEvents, recordSessionEvent } from "../core/event-log.js";
import type { CodeStack, GateVerdict, JevQuestion } from "../core/types.js";

const MAX_EXACT_COMMAND_CHARS = 20000;
const MAX_GUARD_CONTEXT_CHARS = 8000;
const MAX_LOGGED_COMMAND_CHARS = 2000;
const MAX_SPEC_CHARS = 16000;
const MAX_AUDIT_CODE_CHARS = 45000;
const MAX_TASK_CHARS = 12000;
const MAX_BATCH_ITEMS = 100;
const MAX_REMEMBERED_ESCALATIONS = 50;
/** How many recent log events to scan for cross-process guard escalations. */
const ESCALATION_SCAN_EVENTS = 300;

export class McpJevDispatcher {
  private readonly client: JevClient;
  /** Guard ASK_USER/BLOCK verdicts issued by this process (works even if the log is read-only). */
  private readonly guardEscalations: GuardEscalation[] = [];

  constructor(client: JevClient = new JevClient()) {
    this.client = client;
  }

  public getClient(): JevClient {
    return this.client;
  }

  private rememberGuardEscalation(
    verdict: GateVerdict,
    command: string,
    workspace: { workspaceName: string; workspacePath: string },
    agent?: string
  ): void {
    if (verdict !== "ASK_USER" && verdict !== "BLOCK") return;
    this.guardEscalations.push({
      timestamp: new Date().toISOString(),
      verdict,
      command: command.slice(0, MAX_LOGGED_COMMAND_CHARS),
      workspace: workspace.workspaceName,
      workspacePath: workspace.workspacePath,
      agent
    });
    if (this.guardEscalations.length > MAX_REMEMBERED_ESCALATIONS) {
      this.guardEscalations.splice(0, this.guardEscalations.length - MAX_REMEMBERED_ESCALATIONS);
    }
  }

  /** Guard escalations from this process plus other agents' processes (shared event log). */
  private collectGuardEscalations(): GuardEscalation[] {
    const logged: GuardEscalation[] = [];
    for (const evt of readSessionEvents(ESCALATION_SCAN_EVENTS)) {
      if (evt.tool !== "jev_guard_action") continue;
      if (evt.verdict !== "ASK_USER" && evt.verdict !== "BLOCK") continue;
      logged.push({
        timestamp: evt.timestamp,
        verdict: evt.verdict,
        command: evt.optionsOrInput?.command ?? evt.questionOrTitle,
        workspace: evt.workspace,
        workspacePath: evt.workspacePath,
        agent: evt.agent
      });
    }
    return [...this.guardEscalations, ...logged];
  }

  public async decide(input: {
    state: unknown;
    questions: Record<string, JevQuestion>;
    skip_cache?: boolean;
    working_directory?: string;
    agent?: string;
  }) {
    const stateStr = typeof input.state === "string" ? input.state : JSON.stringify(input.state ?? "");
    const resolvedCwd = resolveTargetWorkspace(input.working_directory, [stateStr]);
    const projectDna = buildProjectContextEnvelope(resolvedCwd, [stateStr]);
    const enrichedState =
      input.state && typeof input.state === "object" && !Array.isArray(input.state)
        ? {
            ...(input.state as Record<string, unknown>),
            project_dna:
              (input.state as Record<string, unknown>).project_dna ?? {
                workspace: projectDna.workspaceName,
                stack: projectDna.stackSummary,
                repo_topology: projectDna.repoTopology,
                rules_excerpt: projectDna.projectRulesExcerpt
              }
          }
        : input.state;

    const { response, latencyMs, cached } = await this.client.evaluate(
      enrichedState,
      input.questions,
      { skipCache: input.skip_cache, operation: "jev_decide" }
    );

    const qKeys = Object.keys(input.questions);
    const firstKey = qKeys[0] ?? "decision";
    const firstAns = response.answers[firstKey];
    let selectedOption = firstKey;
    let selectedProbability = 0.8;
    const probabilities: Record<string, number> = {};

    for (const [k, ans] of Object.entries(response.answers)) {
      if (ans.type === "noul") {
        probabilities[k] = Number(ans.noul.toFixed(2));
      } else if (ans.type === "choice") {
        selectedOption = `${k}: ${ans.selected}`;
        selectedProbability = ans.probabilities[ans.selected] ?? 0.8;
        for (const [optK, p] of Object.entries(ans.probabilities)) {
          probabilities[`${k}.${optK}`] = Number(p.toFixed(2));
        }
      } else if (ans.type === "score") {
        probabilities[k] = Number((ans.score / 5).toFixed(2));
      }
    }

    if (firstAns?.type === "noul") {
      selectedProbability = firstAns.noul;
    }

    const questionSummary = Object.entries(input.questions)
      .map(([k, q]) => `${k} (${q.type}): ${q.instructions}`)
      .slice(0, 4);
    const optionsMap: Record<string, string> = {};
    for (const [k, q] of Object.entries(input.questions)) {
      optionsMap[k] = `[${q.type}] ${q.instructions}`;
    }

    recordSessionEvent({
      agent: input.agent,
      workingDirectory: projectDna.workspacePath,
      workspace: projectDna.workspaceName,
      tool: "jev_decide",
      questionOrTitle: `System-1 Parallel Evaluation (${qKeys.length} question${qKeys.length === 1 ? "" : "s"}: ${qKeys.join(", ")})`,
      optionsOrInput: optionsMap,
      verdict: "INFO",
      selectedOption,
      selectedProbability,
      probabilities,
      directive: `Answered ${qKeys.length} parallel System-1 primitives (${questionSummary.join(" | ")})`,
      latencyMs,
      costUsd: response.usage?.cost ?? 0,
      cached
    });

    return {
      model: response.model,
      latencyMs,
      cached,
      usage: response.usage,
      answers: response.answers
    };
  }

  public async guardAction(input: {
    /** The literal command line that will run. Descriptions belong in `context`. */
    exact_command: string;
    context?: string;
    working_directory?: string;
    agent?: string;
  }) {
    const exactCommand = String(input.exact_command ?? "").slice(0, MAX_EXACT_COMMAND_CHARS).trim();
    const context = String(input.context ?? "").slice(0, MAX_GUARD_CONTEXT_CHARS);
    const loggedCommand = exactCommand.slice(0, MAX_LOGGED_COMMAND_CHARS);
    const cwd = resolveTargetWorkspace(input.working_directory, [exactCommand, context]);
    const projectDna = buildProjectContextEnvelope(cwd, [exactCommand, context]);
    const commandShape = assessCommandShape(exactCommand);

    if (commandShape.looksLikeProse) {
      // Scoring a self-written description is meaningless; ask for the real command.
      const decision = buildUnverifiableCommandDecision(commandShape.signals);
      this.rememberGuardEscalation(decision.verdict, exactCommand, projectDna, input.agent);
      recordSessionEvent({
        agent: input.agent,
        workingDirectory: projectDna.workspacePath,
        workspace: projectDna.workspaceName,
        tool: "jev_guard_action",
        questionOrTitle: `Guard Action: \`${loggedCommand.slice(0, 300)}\``,
        optionsOrInput: {
          command: loggedCommand,
          context: context || "(no extra context)",
          command_shape: `prose (${commandShape.signals.join(", ")})`
        },
        verdict: decision.verdict,
        selectedOption: "ASK_USER (exact_command is not a literal command)",
        selectedProbability: 0,
        probabilities: {},
        directive: [...decision.reasons, ...decision.remediation].join(" | "),
        latencyMs: 0,
        costUsd: 0,
        cached: false
      });
      return {
        decision,
        commandShape,
        latencyMs: 0,
        cached: false,
        usage: undefined,
        rawAnswers: {}
      };
    }

    const referencedFiles = extractReferencedDocsAndFiles(cwd, [exactCommand, context], 3, 1500);
    const questions = buildCommandGuardQuestions();
    const { response, latencyMs, cached } = await this.client.evaluate(
      {
        exact_command: exactCommand,
        context,
        working_directory: cwd,
        referenced_scripts_or_docs:
          Object.keys(referencedFiles).length > 0 ? referencedFiles : undefined,
        project_dna: {
          workspace: projectDna.workspaceName,
          stack: projectDna.stackSummary,
          repo_topology: projectDna.repoTopology,
          domain_and_auth_fingerprint: projectDna.domainAndAuthFingerprint,
          learned_human_feedback_rules:
            projectDna.learnedHumanOverrides && projectDna.learnedHumanOverrides.length > 0
              ? projectDna.learnedHumanOverrides
              : undefined,
          rules_excerpt: projectDna.projectRulesExcerpt,
          active_memory: projectDna.activeMemoryExcerpt,
          recent_decisions: projectDna.recentWorkspaceDecisions
        }
      },
      questions,
      { operation: "jev_guard_action" }
    );
    const decision = evaluateCommandGate(response.answers);
    this.rememberGuardEscalation(decision.verdict, exactCommand, projectDna, input.agent);
    const pSafe = Number(decision.metrics.pSafe ?? 0.5);
    const pDestructive = Number(decision.metrics.pDestructive ?? 0);
    const pSecretRisk = Number(decision.metrics.pSecretRisk ?? 0);
    const blastRadius = Number(decision.metrics.blastRadius ?? 2);

    recordSessionEvent({
      agent: input.agent,
      workingDirectory: projectDna.workspacePath,
      workspace: projectDna.workspaceName,
      tool: "jev_guard_action",
      questionOrTitle: `Guard Action: \`${loggedCommand.slice(0, 300)}\``,
      optionsOrInput: {
        command: loggedCommand,
        context: context || "(no extra context)",
        command_shape: "literal"
      },
      verdict: decision.verdict,
      selectedOption: `${decision.verdict} (Blast ${blastRadius.toFixed(1)}/5)`,
      selectedProbability: Number(pSafe.toFixed(2)),
      probabilities: {
        safe_probability: Number(pSafe.toFixed(2)),
        destructive_risk: Number(pDestructive.toFixed(2)),
        secret_exfiltration: Number(pSecretRisk.toFixed(2)),
        blast_radius_norm: Number((blastRadius / 5).toFixed(2))
      },
      directive: decision.reasons.join(" | ") || decision.summary,
      latencyMs,
      costUsd: response.usage?.cost ?? 0,
      cached
    });

    return {
      decision,
      commandShape,
      latencyMs,
      cached,
      usage: response.usage,
      rawAnswers: response.answers
    };
  }

  public async verifyDiff(input: {
    spec: string;
    git_diff?: string;
    test_output?: string;
    working_directory?: string;
    agent?: string;
  }) {
    const boundedSpec = z.string().min(1).max(MAX_SPEC_CHARS).parse(String(input.spec ?? "").slice(0, MAX_SPEC_CHARS));
    input = {
      ...input,
      spec: boundedSpec,
      test_output: input.test_output ? String(input.test_output).slice(0, 12000) : undefined
    };
    const cwd = resolveTargetWorkspace(input.working_directory, [input.spec, input.git_diff]);
    const gitCtx = input.git_diff ? null : collectGitContext(cwd);
    const rawEffectiveDiff = input.git_diff ?? gitCtx?.diff ?? gitCtx?.stagedDiff ?? "";
    const effectiveDiff = input.git_diff
      ? budgetMultiFileDiff(rawEffectiveDiff, "", 45000)
      : rawEffectiveDiff;

    // Extract file paths from inline git_diff when gitCtx is null (e.g., Codex/Gemini inline diffs)
    const inlineFiles = input.git_diff
      ? Array.from(
          new Set(
            Array.from(
              input.git_diff.matchAll(/^(?:diff --git a\/.+? b\/|\+\+\+ (?:b\/)?)([^\r\n\t]+)$/gm),
              (m) => m[1].trim()
            ).filter((f) => f && f !== "/dev/null")
          )
        )
      : [];
    let changedFiles =
      gitCtx && gitCtx.changedFiles.length > 0 ? gitCtx.changedFiles : inlineFiles;
    if (changedFiles.length === 0) {
      const specPathRegex =
        /(?:^|[\s"'`(\[:])((?:docs|src|apps|packages|backend|frontend|scripts|tests|ops|services|lib|components|pages|app|server|client|config)\/[A-Za-z0-9_./-]+\.[A-Za-z0-9]+|[A-Za-z0-9_.-]+\.(?:md|ts|tsx|js|jsx|py|go|json|yaml|yml|toml|sh|ps1|css|sql))(?:$|[\s"'`)\]:,;])/gm;
      const specCandidates = new Set<string>();
      for (const m of `${input.spec}\n${(input.git_diff ?? "").slice(0, 4000)}`.matchAll(specPathRegex)) {
        const rel = m[1]?.trim().replace(/^[./\\]+/, "");
        if (rel && fs.existsSync(path.join(cwd, rel))) {
          specCandidates.add(rel);
        }
      }
      if (specCandidates.size > 0) {
        changedFiles = Array.from(specCandidates);
      }
    }
    const projectDna = buildProjectContextEnvelope(cwd, [input.spec, ...changedFiles]);
    const fullRawForMap = input.git_diff ?? gitCtx?.rawDiff ?? rawEffectiveDiff;
    const structuralDiffMap = extractStructuralDiffMap(fullRawForMap);
    const specCoverageMatrix = buildSpecRequirementMatrix(
      input.spec,
      structuralDiffMap,
      fullRawForMap
    );
    const referencedDocs = extractReferencedDocsAndFiles(cwd, [input.spec], 4, 2200);
    const postEditScopes = extractPostEditHunkScopes(cwd, fullRawForMap, 6, 7000);
    const crossFileContracts = extractCrossFileContracts(cwd, changedFiles, 6, 4500);
    const reverseDependents = extractReverseDependents(cwd, changedFiles, structuralDiffMap);
    const companionTests = extractCompanionTestsContext(cwd, changedFiles, 6);
    const preFlightSyntax = runFastSyntaxProbe(cwd, changedFiles);
    const astSkeletons = extractHybridAstSkeletons(cwd, changedFiles, fullRawForMap, 8);
    const staticLinterReport = runHybridStaticAnalysis(cwd, changedFiles);
    const codeGraphIntel = queryCodeGraphIntelligence(cwd, input.spec, changedFiles);

    const questions = buildDiffVerificationQuestions();
    const { response, latencyMs, cached } = await this.client.evaluate(
      {
        specification: input.spec,
        referenced_handoff_or_spec_docs:
          Object.keys(referencedDocs).length > 0 ? referencedDocs : undefined,
        project_dna: {
          workspace: projectDna.workspaceName,
          stack: projectDna.stackSummary,
          repo_topology: projectDna.repoTopology,
          domain_and_auth_fingerprint: projectDna.domainAndAuthFingerprint,
          learned_human_feedback_rules:
            projectDna.learnedHumanOverrides && projectDna.learnedHumanOverrides.length > 0
              ? projectDna.learnedHumanOverrides
              : undefined,
          rules_excerpt: projectDna.projectRulesExcerpt,
          active_memory: projectDna.activeMemoryExcerpt
        },
        git_branch: gitCtx?.branch || undefined,
        git_status: gitCtx?.statusShort ?? "provided-inline",
        recent_branch_commits:
          gitCtx?.branchCommitsSinceBase && gitCtx.branchCommitsSinceBase.length > 0
            ? gitCtx.branchCommitsSinceBase
            : gitCtx?.recentCommits,
        changed_files: changedFiles,
        pre_flight_syntax_probe:
          preFlightSyntax.status !== "SKIPPED" ? preFlightSyntax : undefined,
        hybrid_static_linter_analysis:
          staticLinterReport.status !== "SKIPPED" ? staticLinterReport : undefined,
        ast_symbol_skeletons: astSkeletons.length > 0 ? astSkeletons : undefined,
        codegraph_intelligence: codeGraphIntel.indexed ? codeGraphIntel : undefined,
        spec_requirement_alignment_matrix:
          specCoverageMatrix.length > 0 ? specCoverageMatrix : undefined,
        structural_change_summary:
          structuralDiffMap.length > 0 ? structuralDiffMap : undefined,
        reverse_dependents_and_callers:
          reverseDependents.modifiedDependents.length > 0 ||
          reverseDependents.unmodifiedDependents.length > 0
            ? reverseDependents
            : undefined,
        existing_companion_test_suites:
          Object.keys(companionTests).length > 0 ? companionTests : undefined,
        imported_contracts_and_types:
          Object.keys(crossFileContracts).length > 0 ? crossFileContracts : undefined,
        post_edit_enclosing_function_scopes:
          Object.keys(postEditScopes).length > 0 ? postEditScopes : undefined,
        git_diff: effectiveDiff || "(no git diff detected)",
        test_output: input.test_output ?? "(not provided)"
      },
      questions,
      { operation: "jev_verify_diff" }
    );

    const specIndicatesDocsOnly =
      /\b(docs[- ]only|documentation[- /](?:only|checkpoint|update)|planning\/handoff-only|only handoff\/planning|only memory docs changed|focused configuration\/docs (?:diff|addition))\b/i.test(
        input.spec
      );
    const allChangedFilesAreDocs =
      changedFiles.length > 0 &&
      changedFiles.every(
        (f) =>
          /\.(md|txt|rst|gitignore|gitattributes)$/i.test(f.trim()) ||
          /^docs\//i.test(f.trim())
      );
    const isDocsOnlyDiff =
      allChangedFilesAreDocs || (changedFiles.length === 0 && specIndicatesDocsOnly);
    const decision = evaluateDiffGate(response.answers, {}, { isDocsOnlyDiff });
    const pFulfillsSpec = Number(decision.metrics.pFulfillsSpec ?? 0.5);
    const pBugRisk = Number(decision.metrics.pBugRisk ?? 0);
    const pSecurityRisk = Number(decision.metrics.pSecurityRisk ?? 0);
    const codeQuality = Number(decision.metrics.codeQuality ?? 3);

    const linterSummary =
      staticLinterReport.status !== "SKIPPED"
        ? `[${staticLinterReport.enginesUsed.join("+")}] ${staticLinterReport.status} (${staticLinterReport.errorCount} errors, ${staticLinterReport.warningCount} warnings across ${staticLinterReport.checkedFiles.length} files)`
        : "SKIPPED (markdown/docs only)";
    const astSummary =
      astSkeletons.length > 0
        ? `${astSkeletons.length} files parsed (${astSkeletons.reduce((acc, s) => acc + s.exportedSignatures.length, 0)} symbols, ${astSkeletons.reduce((acc, s) => acc + s.enclosingModifiedNodes.length, 0)} modified scopes)`
        : "none";
    const cgSummary = codeGraphIntel.indexed
      ? `INDEXED (${codeGraphIntel.graphAffectedTests.length} affected test suites, ${codeGraphIntel.symbolRelations.length} graph relations)`
      : "NOT_INDEXED (auto-indexing triggered)";

    recordSessionEvent({
      agent: input.agent,
      workingDirectory: projectDna.workspacePath,
      workspace: projectDna.workspaceName,
      tool: "jev_verify_diff",
      questionOrTitle: `Verify Diff against Spec: "${input.spec}"`,
      optionsOrInput: {
        spec: input.spec,
        changed_files:
          changedFiles.length > 0
            ? `${changedFiles.length} files (${changedFiles.slice(0, 5).join(", ")})`
            : "inline git diff",
        opensource_linter: linterSummary,
        opensource_ast: astSummary,
        opensource_codegraph: cgSummary
      },
      verdict: decision.verdict,
      selectedOption: `${decision.verdict} (Quality ${codeQuality.toFixed(2)}/5)`,
      selectedProbability: Number(pFulfillsSpec.toFixed(2)),
      probabilities: {
        spec_fulfilled: Number(pFulfillsSpec.toFixed(2)),
        quality_norm: Number((codeQuality / 5).toFixed(2)),
        regression_risk: Number(pBugRisk.toFixed(2)),
        security_risk: Number(pSecurityRisk.toFixed(2))
      },
      directive: decision.reasons.join(" | ") || decision.summary,
      latencyMs,
      costUsd: response.usage?.cost ?? 0,
      cached
    });

    return {
      decision,
      changedFiles,
      latencyMs,
      cached,
      usage: response.usage,
      rawAnswers: response.answers
    };
  }

  public async auditCode(input: {
    code?: string;
    file_path?: string;
    stack?: CodeStack;
    working_directory?: string;
    violation_threshold?: number;
    agent?: string;
  }) {
    const safeFilePath = input.file_path ? z.string().max(512).parse(input.file_path) : undefined;
    const cwd = resolveTargetWorkspace(input.working_directory, [safeFilePath, input.code]);
    let targetCode = (input.code ?? "").slice(0, MAX_AUDIT_CODE_CHARS);
    let changedFiles: string[] = [];
    if (safeFilePath) {
      const absTarget = path.isAbsolute(safeFilePath)
        ? safeFilePath
        : path.resolve(cwd, safeFilePath);
      if (
        !isSensitiveFilePath(absTarget) &&
        isWithinWorkspaceBoundary(cwd, absTarget) &&
        fs.existsSync(absTarget) &&
        fs.statSync(absTarget).isFile()
      ) {
        try {
          const diskContent = fs.readFileSync(absTarget, "utf8").slice(0, 26000);
          const isDiffOnly =
            targetCode.includes("diff --git") || targetCode.includes("@@ -");
          if (!targetCode.trim()) {
            targetCode = diskContent;
          } else if (isDiffOnly && !targetCode.includes("=== FULL FILE CONTENT ON DISK")) {
            targetCode = `${targetCode.slice(0, 14000)}\n\n=== FULL FILE CONTENT ON DISK (${safeFilePath}) ===\n${diskContent}`;
          }
        } catch {
          // ignore read error
        }
      }
    }
    if (!targetCode.trim()) {
      const gitCtx = collectGitContext(cwd);
      targetCode = gitCtx.diff || gitCtx.stagedDiff;
      changedFiles = gitCtx.changedFiles;
    }
    const targetFileList =
      safeFilePath && !changedFiles.includes(safeFilePath)
        ? [safeFilePath, ...changedFiles]
        : changedFiles;
    const projectDna = buildProjectContextEnvelope(cwd, [input.file_path, ...targetFileList]);
    const fileHeaderContext = extractFileHeaderContext(cwd, input.file_path, changedFiles);
    const crossFileContracts = extractCrossFileContracts(cwd, targetFileList, 4, 3200);
    const postEditScopes = extractPostEditHunkScopes(cwd, targetCode, 4, 4500);
    const preFlightSyntax = runFastSyntaxProbe(cwd, targetFileList);
    const astSkeletons = extractHybridAstSkeletons(cwd, targetFileList, targetCode, 6);
    const staticLinterReport = runHybridStaticAnalysis(cwd, targetFileList);

    const res = await auditCodeWithSkills(this.client, {
      code: targetCode,
      filePath: input.file_path,
      stack: input.stack,
      violationThreshold: input.violation_threshold,
      projectContext: {
        workspace: projectDna.workspaceName,
        stack: projectDna.stackSummary,
        repo_topology: projectDna.repoTopology,
        domain_and_auth_fingerprint: projectDna.domainAndAuthFingerprint,
        learned_human_feedback_rules:
          projectDna.learnedHumanOverrides && projectDna.learnedHumanOverrides.length > 0
            ? projectDna.learnedHumanOverrides
            : undefined,
        pre_flight_syntax_probe:
          preFlightSyntax.status !== "SKIPPED" ? preFlightSyntax : undefined,
        hybrid_static_linter_analysis:
          staticLinterReport.status !== "SKIPPED" ? staticLinterReport : undefined,
        ast_symbol_skeletons: astSkeletons.length > 0 ? astSkeletons : undefined,
        rules_excerpt: projectDna.projectRulesExcerpt,
        imported_contracts:
          Object.keys(crossFileContracts).length > 0 ? crossFileContracts : undefined,
        enclosing_function_scopes:
          Object.keys(postEditScopes).length > 0 ? postEditScopes : undefined
      },
      fileHeaderContext
    });

    const probs: Record<string, number> = {
      security_score_norm: Number((res.securityScore / 5).toFixed(2))
    };
    for (const v of res.violatedVectors) {
      probs[v.vector] = Number(v.probability.toFixed(2));
    }

    const violatedNames = res.violatedVectors.map((v) => v.vector);

    const auditLinterSummary =
      staticLinterReport.status !== "SKIPPED"
        ? `[${staticLinterReport.enginesUsed.join("+")}] ${staticLinterReport.status} (${staticLinterReport.errorCount} errors, ${staticLinterReport.warningCount} warnings)`
        : "SKIPPED";
    const auditAstSummary =
      astSkeletons.length > 0
        ? `${astSkeletons.length} files parsed (${astSkeletons.reduce((acc, s) => acc + s.exportedSignatures.length, 0)} symbols)`
        : "none";

    recordSessionEvent({
      agent: input.agent,
      workingDirectory: projectDna.workspacePath,
      workspace: projectDna.workspaceName,
      tool: "jev_audit_code",
      questionOrTitle: `Skill-Backed Security & Quality Audit (${input.file_path || res.stack})`,
      optionsOrInput: {
        stack: res.stack,
        target: input.file_path || "local git diff",
        violations:
          violatedNames.length > 0 ? violatedNames.join(", ") : "0 violations detected",
        opensource_linter: auditLinterSummary,
        opensource_ast: auditAstSummary
      },
      verdict: res.verdict,
      selectedOption: `${res.verdict} (${res.securityScore.toFixed(2)}/5)`,
      selectedProbability: Number((res.securityScore / 5).toFixed(2)),
      probabilities: probs,
      directive: res.summary,
      latencyMs: res.latencyMs,
      costUsd: res.usage?.cost ?? 0,
      cached: res.cached
    });

    return res;
  }

  public async pruneContext(input: {
    task: string;
    candidates: ContextCandidate[];
    threshold?: number;
    working_directory?: string;
    agent?: string;
  }) {
    const boundedTask = z.string().min(1).max(MAX_TASK_CHARS).parse(String(input.task ?? "").slice(0, MAX_TASK_CHARS));
    const boundedCandidates = input.candidates.slice(0, MAX_BATCH_ITEMS);
    input = { ...input, task: boundedTask, candidates: boundedCandidates };
    const threshold = Math.min(1, Math.max(0, input.threshold ?? 0.60));
    const candidateIds = input.candidates.slice(0, 15).map((c) => c.id);
    const cwd = resolveTargetWorkspace(input.working_directory, [input.task, ...candidateIds]);
    const projectDna = buildProjectContextEnvelope(cwd, [input.task]);
    const questions = buildContextPruneQuestions(input.task, input.candidates);
    const { response, latencyMs, cached } = await this.client.evaluate(
      {
        task: input.task,
        workspace: projectDna.workspaceName,
        stack: projectDna.stackSummary,
        candidates: input.candidates
      },
      questions,
      { operation: "jev_prune_context" }
    );

    const kept = extractContextPruneResults(input.candidates, response.answers, threshold);
    const probs: Record<string, number> = {};
    for (const entry of kept.slice(0, 6)) {
      probs[entry.item.id] = Number(entry.probability.toFixed(2));
    }

    recordSessionEvent({
      agent: input.agent,
      workingDirectory: projectDna.workspacePath,
      workspace: projectDna.workspaceName,
      tool: "jev_prune_context",
      questionOrTitle: `Prune Context for Task: "${input.task}"`,
      optionsOrInput: {
        total_candidates: `${input.candidates.length} items`,
        kept_items:
          kept.map((k) => `${k.item.id} (${Math.round(k.probability * 100)}%)`).join(", ") || "none"
      },
      verdict: "ALLOW",
      selectedOption: `Kept ${kept.length}/${input.candidates.length} candidates`,
      selectedProbability: kept[0]?.probability ?? 1,
      probabilities: probs,
      directive: `Filtered ${input.candidates.length} candidates down to ${kept.length} relevant items (threshold >= ${threshold})`,
      latencyMs,
      costUsd: response.usage?.cost ?? 0,
      cached
    });

    return {
      totalCandidates: input.candidates.length,
      keptCount: kept.length,
      prunedCount: input.candidates.length - kept.length,
      threshold,
      latencyMs,
      cached,
      kept
    };
  }

  public async classifyBatch(input: {
    items: string[];
    criteria: Record<string, string>;
    instructions: string;
    agent?: string;
  }) {
    const boundedItems = input.items.slice(0, MAX_BATCH_ITEMS).map((s) => String(s).slice(0, 2000));
    const boundedInstructions = z.string().min(1).max(MAX_TASK_CHARS).parse(String(input.instructions ?? "").slice(0, MAX_TASK_CHARS));
    input = { ...input, items: boundedItems, instructions: boundedInstructions };
    const questions = buildBatchClassifyQuestions(
      input.items,
      input.criteria,
      input.instructions
    );
    const { response, latencyMs, cached } = await this.client.evaluate(
      { items: input.items },
      questions,
      { operation: "jev_classify_batch" }
    );

    const results = input.items.slice(0, 100).map((item, idx) => {
      const ans = response.answers[`item_${idx}`];
      if (ans && ans.type === "choice") {
        return {
          index: idx,
          item,
          selected: ans.selected,
          probabilities: ans.probabilities
        };
      }
      return {
        index: idx,
        item,
        selected: "unknown",
        probabilities: {}
      };
    });

    const cwd = resolveTargetWorkspace(undefined, [input.instructions]);
    recordSessionEvent({
      agent: input.agent,
      workingDirectory: cwd,
      workspace: path.basename(cwd) || "workspace",
      tool: "jev_classify_batch",
      questionOrTitle: input.instructions.slice(0, 300),
      optionsOrInput: {
        items_count: String(results.length),
        criteria_keys: Object.keys(input.criteria).join(", ")
      },
      verdict: "INFO",
      selectedOption: `Classified ${results.length} item(s)`,
      selectedProbability: 1,
      probabilities: {},
      directive: `Batch classified ${results.length} item(s) across [${Object.keys(input.criteria).join(", ")}]`,
      latencyMs,
      costUsd: response.usage?.cost ?? 0,
      cached
    });

    return {
      count: results.length,
      latencyMs,
      cached,
      results
    };
  }

  public async routeTask(input: {
    task_description: string;
    repo_context?: string;
    working_directory?: string;
    agent?: string;
  }) {
    const boundedTaskDesc = z
      .string()
      .min(1)
      .max(MAX_TASK_CHARS)
      .parse(String(input.task_description ?? "").slice(0, MAX_TASK_CHARS));
    input = {
      ...input,
      task_description: boundedTaskDesc,
      repo_context: input.repo_context ? String(input.repo_context).slice(0, MAX_TASK_CHARS) : undefined
    };
    const cwd = resolveTargetWorkspace(input.working_directory, [
      input.task_description,
      input.repo_context
    ]);
    const projectDna = buildProjectContextEnvelope(cwd, [
      input.task_description,
      input.repo_context
    ]);
    const referencedDocs = extractReferencedDocsAndFiles(
      cwd,
      [input.task_description, input.repo_context],
      3,
      1800
    );
    const codeGraphIntel = queryCodeGraphIntelligence(cwd, input.task_description);
    const questions = buildTaskRouteQuestions();
    const { response, latencyMs, cached } = await this.client.evaluate(
      {
        task_description: input.task_description,
        repo_context: input.repo_context ?? "",
        referenced_docs_or_files:
          Object.keys(referencedDocs).length > 0 ? referencedDocs : undefined,
        codegraph_intelligence: codeGraphIntel.indexed ? codeGraphIntel : undefined,
        project_dna: {
          workspace: projectDna.workspaceName,
          stack: projectDna.stackSummary,
          repo_topology: projectDna.repoTopology,
          domain_and_auth_fingerprint: projectDna.domainAndAuthFingerprint,
          learned_human_feedback_rules:
            projectDna.learnedHumanOverrides && projectDna.learnedHumanOverrides.length > 0
              ? projectDna.learnedHumanOverrides
              : undefined,
          rules_excerpt: projectDna.projectRulesExcerpt,
          active_memory: projectDna.activeMemoryExcerpt
        }
      },
      questions,
      { operation: "jev_route_task" }
    );

    const strategyAns = response.answers.execution_strategy;
    const tierAns = response.answers.recommended_model_tier;
    const secAns = response.answers.requires_security_review;
    const uiAns = response.answers.requires_ui_ux_design_system;
    const ambAns = response.answers.ambiguity_needs_user_question;
    const compAns = response.answers.complexity_score;

    const strategy = strategyAns?.type === "choice" ? strategyAns.selected : "direct_edit";
    const recommendedModelTier =
      tierAns?.type === "choice" ? tierAns.selected : "balanced_coding";
    const complexityScore = compAns?.type === "score" ? compAns.score : 2.5;

    recordSessionEvent({
      agent: input.agent,
      workingDirectory: projectDna.workspacePath,
      workspace: projectDna.workspaceName,
      tool: "jev_route_task",
      questionOrTitle: `Route Task: "${input.task_description}"`,
      optionsOrInput: {
        task: input.task_description,
        repo_context: input.repo_context || `${projectDna.workspaceName} (${projectDna.stackSummary.slice(0, 120)})`
      },
      verdict: "INFO",
      selectedOption: `${strategy} (${recommendedModelTier})`,
      selectedProbability:
        strategyAns?.type === "choice"
          ? Number((strategyAns.probabilities[strategy] ?? 0.8).toFixed(2))
          : 0.8,
      probabilities:
        strategyAns?.type === "choice" ? strategyAns.probabilities : { [strategy]: 0.8 },
      directive: `Strategy: ${strategy} | Tier: ${recommendedModelTier} | Complexity: ${complexityScore.toFixed(1)}/5`,
      latencyMs,
      costUsd: response.usage?.cost ?? 0,
      cached
    });

    return {
      strategy,
      recommendedModelTier,
      requiresSecuritySkill: secAns?.type === "noul" ? secAns.noul >= 0.55 : false,
      requiresUiUxSkill: uiAns?.type === "noul" ? uiAns.noul >= 0.55 : false,
      shouldAskClarifyingQuestion: ambAns?.type === "noul" ? ambAns.noul >= 0.60 : false,
      complexityScore,
      latencyMs,
      cached,
      rawAnswers: response.answers
    };
  }

  public getStats() {
    return this.client.getTelemetry().getSummary();
  }

  public async autopilotDecide(input: {
    question: string;
    options: Record<string, string>;
    context?: string;
    developer_preferences?: string;
    min_confidence?: number;
    agent?: string;
    working_directory?: string;
  }) {
    const cwd = resolveTargetWorkspace(input.working_directory, [
      input.question,
      input.context,
      ...Object.values(input.options)
    ]);
    const projectDna = buildProjectContextEnvelope(cwd, [input.question, input.context]);
    const referencedDocs = extractReferencedDocsAndFiles(
      cwd,
      [input.question, input.context],
      3,
      1800
    );
    const questions = buildAutopilotProxyQuestions(input.options);
    const { response, latencyMs, cached } = await this.client.evaluate(
      {
        decision_question_for_user: input.question,
        candidate_options: input.options,
        project_context: input.context ?? "",
        referenced_docs_or_files:
          Object.keys(referencedDocs).length > 0 ? referencedDocs : undefined,
        project_dna: {
          workspace: projectDna.workspaceName,
          stack: projectDna.stackSummary,
          repo_topology: projectDna.repoTopology,
          domain_and_auth_fingerprint: projectDna.domainAndAuthFingerprint,
          learned_human_feedback_rules:
            projectDna.learnedHumanOverrides && projectDna.learnedHumanOverrides.length > 0
              ? projectDna.learnedHumanOverrides
              : undefined,
          rules_excerpt: projectDna.projectRulesExcerpt,
          active_memory: projectDna.activeMemoryExcerpt,
          recent_decisions: projectDna.recentWorkspaceDecisions
        },
        developer_profile: input.developer_preferences ?? DEFAULT_DEVELOPER_PROFILE
      },
      questions,
      { operation: "jev_autopilot_decide" }
    );

    // Agents may raise the confidence bar but never lower it below the policy floor.
    const requestedMin = Number.isFinite(input.min_confidence) ? Number(input.min_confidence) : 0;
    const minChoiceProbability = Math.min(
      1,
      Math.max(JEV_POLICY.autopilot.minChoiceProbability, requestedMin)
    );
    const guardEscalation = findBlockingGuardEscalation(this.collectGuardEscalations(), {
      workspaceName: projectDna.workspaceName,
      workspacePath: projectDna.workspacePath,
      workspaceIsUnknown: isGenericHostDirectory(projectDna.workspacePath)
    });
    const verdict = evaluateAutopilotProxy(
      response.answers,
      { minChoiceProbability },
      { enabled: isAutopilotEnabled(), guardEscalation }
    );

    recordSessionEvent({
      agent: input.agent,
      workingDirectory: projectDna.workspacePath,
      workspace: projectDna.workspaceName,
      tool: "jev_autopilot_decide",
      questionOrTitle: input.question,
      optionsOrInput: input.options,
      verdict: verdict.mode,
      selectedOption: verdict.selectedOption,
      selectedProbability: verdict.selectedProbability,
      probabilities: verdict.allProbabilities,
      directive: verdict.agentDirective,
      latencyMs,
      costUsd: response.usage?.cost ?? 0,
      cached
    });

    return {
      ...verdict,
      latencyMs,
      cached,
      usage: response.usage
    };
  }
}

export function createMcpJevServer(client?: JevClient): McpServer {
  const dispatcher = new McpJevDispatcher(client);
  const server = new McpServer({
    name: "mcp-jev",
    version: "1.1.1"
  });

  server.tool(
    "jev_decide",
    "System-1 parallel decision engine (TypeSafe AI Jev). Evaluates state against typed questions (noul, choice, score) and returns mathematically calibrated probabilities in ~150ms.",
    {
      state: z.any().describe("Application context, git diff, JSON object, or text to evaluate"),
      questions: z
        .record(
          z.string(),
          z.object({
            type: z.enum(["noul", "choice", "score"]),
            instructions: z.string(),
            criteria: z.record(z.string(), z.string()).optional()
          })
        )
        .describe("Map of question keys to typed Jev primitives (noul, choice, score)"),
      skip_cache: z.boolean().optional().describe("Bypass local SHA-256 LRU cache"),
      working_directory: z.string().optional().describe("Optional project workspace directory")
    },
    async (args) => {
      const res = await dispatcher.decide({
        state: args.state,
        questions: args.questions as Record<string, JevQuestion>,
        skip_cache: args.skip_cache,
        working_directory: args.working_directory
      });
      return {
        content: [{ type: "text", text: JSON.stringify(res, null, 2) }]
      };
    }
  );

  server.tool(
    "jev_verify_diff",
    "Zero-token Spec-to-Diff verification gate. Automatically collects local `git diff` (if omitted) and evaluates spec fulfillment, bug risk, security risk, and test coverage in 1 parallel pass. BLOCK = elevated security or regression risk: fix before finishing. ASK_USER = warning (spec alignment uncertain or tests missing): tell the user which parts are uncertain instead of rewriting the spec to pass. ALLOW = clean.",
    {
      spec: z
        .string()
        .describe(
          "The user's original request or acceptance criteria for this step, verbatim where possible. Do not paraphrase the diff."
        ),
      git_diff: z
        .string()
        .optional()
        .describe("Optional git diff string. Leave empty to auto-collect local `git diff HEAD`"),
      test_output: z.string().optional().describe("Optional test runner output"),
      working_directory: z.string().optional().describe("Workspace path for local git collection")
    },
    async (args) => {
      const res = await dispatcher.verifyDiff(args);
      return {
        content: [{ type: "text", text: JSON.stringify(res, null, 2) }]
      };
    }
  );

  server.tool(
    "jev_audit_code",
    "Skill-Backed Security, Animation & Architecture Auditor. Scores code or local git diff against 10+ security/GSAP/architecture vectors and automatically extracts remediation rules from your installed skills (`security-best-practices`, `gsap-performance`, `codebase-design`) when violations are detected.",
    {
      code: z
        .string()
        .optional()
        .describe("Code snippet or diff to audit. If omitted, automatically audits current local `git diff`"),
      file_path: z.string().optional().describe("File path to help auto-detect framework stack"),
      stack: z
        .enum([
          "nextjs",
          "express",
          "react",
          "vue",
          "frontend",
          "fastapi",
          "django",
          "flask",
          "golang",
          "gsap",
          "general"
        ])
        .optional()
        .describe("Explicit stack override"),
      working_directory: z.string().optional().describe("Workspace directory if auditing local git diff"),
      violation_threshold: z
        .number()
        .optional()
        .describe("Probability threshold (0-1) to trigger local skill reference extraction (default 0.55)")
    },
    async (args) => {
      const res = await dispatcher.auditCode(args);
      return {
        content: [{ type: "text", text: JSON.stringify(res, null, 2) }]
      };
    }
  );

  server.tool(
    "jev_guard_action",
    "Pre-flight safety & blast-radius gate for a terminal command, migration, or destructive edit. Put the literal command line in `exact_command` and the explanation in `context`. Returns ALLOW, ASK_USER, or BLOCK with calibrated probabilities. ASK_USER means a human must confirm before running it (jev_autopilot_decide cannot replace that confirmation); a prose description instead of a command always returns ASK_USER.",
    {
      exact_command: z
        .string()
        .min(1)
        .max(MAX_EXACT_COMMAND_CHARS)
        .describe(
          "The exact command line that will be executed, verbatim (program + arguments), e.g. `git add -- docs/a.md; git commit -m \"docs: update\"`. Not a description of the action."
        ),
      context: z
        .string()
        .max(MAX_GUARD_CONTEXT_CHARS)
        .optional()
        .describe("Why the command is run, what it should touch, and any explicit user authorization"),
      working_directory: z.string().max(1000).optional().describe("Target working directory")
    },
    async (args) => {
      const res = await dispatcher.guardAction(args);
      return {
        content: [{ type: "text", text: JSON.stringify(res, null, 2) }]
      };
    }
  );

  server.tool(
    "jev_prune_context",
    "Out-of-context parallel relevance filter & reranker. Scores up to 100 candidate files, skills, or search results in a single ~150ms API call and returns only relevant items sorted by probability.",
    {
      task: z.string().describe("Current coding task or bug description"),
      candidates: z
        .array(
          z.object({
            id: z.string().describe("File path, skill name, or identifier"),
            summary: z.string().optional().describe("Brief summary or snippet")
          })
        )
        .describe("Candidate items to filter and rank (up to 100)"),
      threshold: z
        .number()
        .optional()
        .describe("Minimum relevance probability (0-1) to keep an item (default 0.60)"),
      working_directory: z.string().optional().describe("Optional project workspace directory")
    },
    async (args) => {
      const res = await dispatcher.pruneContext(args);
      return {
        content: [{ type: "text", text: JSON.stringify(res, null, 2) }]
      };
    }
  );

  server.tool(
    "jev_classify_batch",
    "High-speed parallel batch classifier. Categorizes up to 100 items (logs, lint errors, files, tickets) into defined criteria in a single pass.",
    {
      items: z.array(z.string()).describe("List of items to classify (up to 100)"),
      criteria: z.record(z.string(), z.string()).describe("Map of category key -> description"),
      instructions: z.string().describe("Classification instruction")
    },
    async (args) => {
      const res = await dispatcher.classifyBatch(args);
      return {
        content: [{ type: "text", text: JSON.stringify(res, null, 2) }]
      };
    }
  );

  server.tool(
    "jev_route_task",
    "Multi-agent workflow & model tier dispatcher. Determines the optimal execution strategy (direct edit, TDD, parallel subagents, brainstorm) and whether security/UI skills are required.",
    {
      task_description: z.string().describe("User prompt or ticket description"),
      repo_context: z.string().optional().describe("Optional summary of repo structure or tech stack"),
      working_directory: z.string().optional().describe("Optional project workspace directory")
    },
    async (args) => {
      const res = await dispatcher.routeTask(args);
      return {
        content: [{ type: "text", text: JSON.stringify(res, null, 2) }]
      };
    }
  );

  server.tool(
    "jev_stats",
    "Returns session telemetry: total System-1 calls, SHA-256 cache hit rate, average latency (ms), token usage, USD cost, and ALLOW/BLOCK gate counts.",
    {},
    async () => {
      const stats = dispatcher.getStats();
      return {
        content: [{ type: "text", text: JSON.stringify(stats, null, 2) }]
      };
    }
  );

  server.tool(
    "jev_autopilot_decide",
    "Human-Proxy Autopilot Decision Maker (disabled by default; enabled only when the server runs with JEV_AUTOPILOT=1). Call it before asking the user a multiple-choice technical question. Returns `AUTOPILOT_PROCEED` only when autopilot is enabled, the choice is a clear reversible engineering decision (P >= 0.65), and jev_guard_action has not returned ASK_USER/BLOCK in this workspace within the last 15 minutes. Otherwise returns `ASK_HUMAN` with Jev's recommended option to list first.",
    {
      question: z.string().describe("The question the coding agent is considering asking the user"),
      options: z
        .record(z.string(), z.string())
        .describe("Map of option_id -> description of each candidate approach or choice"),
      context: z.string().optional().describe("Current project/code context relevant to the decision"),
      developer_preferences: z
        .string()
        .optional()
        .describe("Optional override for the developer's architectural/taste preferences"),
      min_confidence: z
        .number()
        .min(0)
        .max(1)
        .optional()
        .describe("Raise the minimum probability (0-1) required to auto-decide; values below the 0.65 floor are ignored"),
      working_directory: z.string().optional().describe("Optional project workspace directory")
    },
    async (args) => {
      const res = await dispatcher.autopilotDecide(args);
      return {
        content: [{ type: "text", text: JSON.stringify(res, null, 2) }]
      };
    }
  );

  return server;
}

export async function startStdioServer(client?: JevClient): Promise<void> {
  const server = createMcpJevServer(client);
  const transport = new StdioServerTransport();
  await server.connect(transport);
}
