import path from "node:path";
import { JevClient } from "../core/jev-client.js";
import { buildCommandGuardQuestions } from "../core/presets.js";
import { buildUnverifiableCommandDecision, evaluateCommandGate } from "../core/policy-engine.js";
import { assessCommandShape } from "../core/command-shape.js";
import { recordSessionEvent } from "../core/event-log.js";
import { auditCodeWithSkills } from "../core/skill-auditor.js";
import type { GateVerdict } from "../core/types.js";

export type HookFailMode = "open" | "ask" | "closed";

export interface HookPayload {
  tool_name?: string;
  toolName?: string;
  tool_input?: {
    command?: string;
    CommandLine?: string;
    file_path?: string;
    Path?: string;
    content?: string;
    Content?: string;
    new_string?: string;
    Replacement?: string;
  };
  command?: string;
  code?: string;
  file_path?: string;
}

export interface HookRunResult {
  exitCode: 0 | 1 | 2;
  verdict: GateVerdict;
  stdout: string;
  stderr: string;
}

function formatHookStdout(decision: "allow" | "ask" | "deny", reason: string): string {
  return JSON.stringify({
    hookSpecificOutput: {
      hookEventName: "PreToolUse",
      permissionDecision: decision,
      permissionDecisionReason: reason
    },
    permissionDecision: decision,
    reason
  });
}

export async function runPreToolHook(
  rawInput: string,
  client: JevClient = new JevClient(),
  failMode: HookFailMode = (process.env.JEV_FAIL_MODE as HookFailMode) ?? "ask"
): Promise<HookRunResult> {
  let payload: HookPayload = {};
  try {
    payload = rawInput.trim().startsWith("{")
      ? (JSON.parse(rawInput) as HookPayload)
      : { command: rawInput.trim() };
  } catch {
    payload = { command: rawInput.trim() };
  }

  const command =
    payload.command ??
    payload.tool_input?.command ??
    payload.tool_input?.CommandLine ??
    "";

  const codeContent =
    payload.code ??
    payload.tool_input?.content ??
    payload.tool_input?.Content ??
    payload.tool_input?.new_string ??
    payload.tool_input?.Replacement ??
    "";

  const filePath =
    payload.file_path ?? payload.tool_input?.file_path ?? payload.tool_input?.Path ?? "";

  try {
    // 1. If intercepting a shell command
    if (command.trim().length > 0) {
      const shape = assessCommandShape(command);
      const cwd = process.cwd();
      const workspace = path.basename(cwd) || "workspace";

      if (shape.looksLikeProse) {
        const decision = buildUnverifiableCommandDecision(shape.signals);
        recordSessionEvent({
          agent: "CLI",
          workingDirectory: cwd,
          workspace,
          tool: "jev_guard_action",
          questionOrTitle: `Hook Gate: \`${command.slice(0, 300)}\``,
          optionsOrInput: {
            command: command.slice(0, 2000),
            command_shape: `prose (${shape.signals.join(", ")})`
          },
          verdict: "ASK_USER",
          selectedOption: "ASK_USER (prose command input)",
          selectedProbability: 0,
          probabilities: {},
          directive: decision.summary,
          latencyMs: 0,
          costUsd: 0,
          cached: false
        });
        return {
          exitCode: 0,
          verdict: "ASK_USER",
          stdout: formatHookStdout("ask", decision.summary),
          stderr: ""
        };
      }

      const questions = buildCommandGuardQuestions();
      const { response, latencyMs, cached } = await client.evaluate(
        {
          tool: payload.tool_name ?? payload.toolName ?? "Bash",
          exact_command: command
        },
        questions,
        { operation: "jev_gate_command" }
      );
      const decision = evaluateCommandGate(response.answers);
      const pSafe = Number(decision.metrics.pSafe ?? 0.5);
      const pDestructive = Number(decision.metrics.pDestructive ?? 0);
      const pSecretRisk = Number(decision.metrics.pSecretRisk ?? 0);
      const blastRadius = Number(decision.metrics.blastRadius ?? 2);

      recordSessionEvent({
        agent: "CLI",
        workingDirectory: cwd,
        workspace,
        tool: "jev_guard_action",
        questionOrTitle: `Hook Gate: \`${command.slice(0, 300)}\``,
        optionsOrInput: {
          command: command.slice(0, 2000),
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

      if (decision.verdict === "ALLOW") {
        return {
          exitCode: 0,
          verdict: "ALLOW",
          stdout: formatHookStdout("allow", decision.summary),
          stderr: ""
        };
      }

      if (decision.verdict === "BLOCK") {
        const errMessage = [
          decision.summary,
          ...decision.reasons.map((r) => `  - Reason: ${r}`),
          ...decision.remediation.map((r) => `  - Fix: ${r}`)
        ].join("\n");
        return {
          exitCode: 2,
          verdict: "BLOCK",
          stdout: formatHookStdout("deny", decision.summary),
          stderr: errMessage
        };
      }

      return {
        exitCode: 0,
        verdict: "ASK_USER",
        stdout: formatHookStdout("ask", decision.summary),
        stderr: ""
      };
    }

    // 2. If intercepting a file write/edit with code
    if (codeContent.trim().length > 0) {
      const audit = await auditCodeWithSkills(client, {
        code: codeContent,
        filePath
      });

      if (audit.verdict === "BLOCK") {
        const excerptText = audit.skillExcerpts
          .map(
            (ex) =>
              `  * [${ex.vector} P=${ex.probability.toFixed(2)}] ${ex.title}\n    Rule (${ex.skillFile}): ${ex.excerpt.slice(0, 350)}`
          )
          .join("\n");
        const errMessage = `[Jev Skill-Backed Security Gate: BLOCK] Stack=${audit.stack} Score=${audit.securityScore.toFixed(1)}/5\n${excerptText}`;
        return {
          exitCode: 2,
          verdict: "BLOCK",
          stdout: formatHookStdout("deny", errMessage),
          stderr: errMessage
        };
      }

      const summary = `[Jev Skill Gate: ${audit.verdict}] Stack=${audit.stack} Score=${audit.securityScore.toFixed(1)}/5`;
      return {
        exitCode: 0,
        verdict: audit.verdict,
        stdout: formatHookStdout(audit.verdict === "ALLOW" ? "allow" : "ask", summary),
        stderr: ""
      };
    }

    // Nothing to guard
    return {
      exitCode: 0,
      verdict: "ALLOW",
      stdout: formatHookStdout("allow", "No command or code payload to guard."),
      stderr: ""
    };
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    if (failMode === "closed") {
      return {
        exitCode: 2,
        verdict: "BLOCK",
        stdout: formatHookStdout("deny", `Jev Gate fail-closed error: ${msg}`),
        stderr: `[Jev Gate Error - Fail Closed]: ${msg}`
      };
    }
    if (failMode === "open") {
      return {
        exitCode: 0,
        verdict: "ALLOW",
        stdout: formatHookStdout("allow", `Jev Gate fail-open fallback: ${msg}`),
        stderr: ""
      };
    }
    return {
      exitCode: 0,
      verdict: "ASK_USER",
      stdout: formatHookStdout("ask", `Jev Gate fallback to human confirmation: ${msg}`),
      stderr: ""
    };
  }
}
