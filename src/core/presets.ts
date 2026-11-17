import type { JevQuestion } from "./types.js";

export interface ContextCandidate {
  id: string;
  summary?: string;
  content?: string;
}

export function buildCommandGuardQuestions(): Record<string, JevQuestion> {
  return {
    is_safe_to_execute: {
      type: "noul",
      instructions:
        "Is this command or file operation safe to execute automatically in a developer workspace without risking data loss, system corruption, or credential exposure?"
    },
    is_destructive_or_irreversible: {
      type: "noul",
      instructions:
        "Could this action permanently delete untracked work, drop database tables, force-push git history, or modify critical system files irreversibly?"
    },
    exposes_secrets_or_network_risk: {
      type: "noul",
      instructions:
        "Does this action exfiltrate data, expose secrets/API keys/env vars, download untrusted remote scripts (curl|sh), or open unauthorized network listeners?"
    },
    blast_radius: {
      type: "score",
      instructions:
        "Rate the potential blast radius of this action from 1 (read-only or isolated local file) to 5 (production infrastructure, git history rewrite, or system-wide impact).",
      criteria: [
        "1: Read-only inspection or harmless local test run",
        "2: Isolated edit or standard build/test command within project workspace",
        "3: Multi-file refactor, dependency installation, or local git commit",
        "4: Destructive file deletion, git reset/clean, or external API mutation",
        "5: Irreversible force push, production DB mutation, secret exposure, or OS-level change"
      ]
    },
    recommended_decision: {
      type: "choice",
      instructions: "What gate enforcement action should the coding agent firewall take?",
      criteria: {
        allow_silently: "Safe routine development command or edit; allow immediately without interrupting the user",
        ask_user_confirmation: "Moderate blast radius or ambiguous side effects; ask the human developer to confirm first",
        block_immediately: "High risk, destructive, or security violation; block execution and require a safer approach"
      }
    }
  };
}

export function buildDiffVerificationQuestions(): Record<string, JevQuestion> {
  return {
    fulfills_spec: {
      type: "noul",
      instructions:
        "Do the changes shown in the git diff (whether production code, tests, or documentation/handoff/review Markdown when the specification explicitly states this step is a documentation, planning, or review checkpoint) fulfill the requested scope of this step?"
    },
    introduces_bug_or_regression: {
      type: "noul",
      instructions:
        "Does the newly added (+) production code in the git diff introduce a real logic bug, broken import, or regression (ignoring defensive error handling and passing unit tests)?"
    },
    has_security_risk: {
      type: "noul",
      instructions:
        "Does the newly added (+) production code in the git diff introduce a new, unmitigated security vulnerability (ignoring security patches, removed (-) lines, and test payloads in *.test.ts files)?"
    },
    missing_tests_or_edge_cases: {
      type: "noul",
      instructions:
        "Are automated tests completely missing despite the changes requiring new test coverage (note: check test_output and *.test.ts in changed_files)?"
    },
    code_quality: {
      type: "score",
      instructions:
        "Rate the overall code quality, modularity, and maintainability of the diff from 1 (poor/hacky) to 5 (clean, well-typed, production-grade).",
      criteria: [
        "1: Broken, messy, or violates core project conventions",
        "2: Fragile implementation with obvious technical debt",
        "3: Acceptable working code with minor rough edges",
        "4: Clean, well-structured, and properly typed code",
        "5: Exemplary deep-module architecture with thorough test coverage"
      ]
    },
    next_action: {
      type: "choice",
      instructions: "What should the coding agent do next before marking the task complete?",
      criteria: {
        ready_to_commit: "All requirements met, tests covered, and no material bugs or security risks",
        fix_bugs: "Fix logic errors, regressions, or incomplete spec requirements in the code",
        add_tests: "Write or update automated tests covering the changed behavior and edge cases",
        address_security: "Fix security vulnerabilities or input validation gaps before proceeding",
        clarify_requirements: "Stop and ask the user to clarify ambiguous or conflicting requirements"
      }
    }
  };
}

export function buildContextPruneQuestions(
  task: string,
  candidates: ContextCandidate[]
): Record<string, JevQuestion> {
  const questions: Record<string, JevQuestion> = {};
  const bounded = candidates.slice(0, 100);
  for (let i = 0; i < bounded.length; i += 1) {
    const item = bounded[i];
    const label = item.summary
      ? `${item.id} (${item.summary.slice(0, 180)})`
      : item.id;
    questions[`item_${i}`] = {
      type: "noul",
      instructions: `Is candidate [${label}] directly relevant and necessary in the context window to complete the task: "${task.slice(0, 300)}"?`
    };
  }
  return questions;
}

export function buildBatchClassifyQuestions(
  items: string[],
  criteria: Record<string, string>,
  instructions: string
): Record<string, JevQuestion> {
  const questions: Record<string, JevQuestion> = {};
  const bounded = items.slice(0, 100);
  for (let i = 0; i < bounded.length; i += 1) {
    questions[`item_${i}`] = {
      type: "choice",
      instructions: `${instructions} (Item #${i}: "${bounded[i].slice(0, 250)}")`,
      criteria
    };
  }
  return questions;
}

export function buildTaskRouteQuestions(): Record<string, JevQuestion> {
  return {
    execution_strategy: {
      type: "choice",
      instructions: "Which engineering workflow strategy best fits this coding task?",
      criteria: {
        direct_edit: "Small, clear, well-scoped change that can be implemented directly in 1-2 files",
        tdd_red_green: "Feature or bugfix with testable logic where writing failing tests first prevents regressions",
        parallel_subagents: "Task with 2+ independent subsystems or files that can be delegated in parallel",
        brainstorm_spec_first: "Ambiguous, creative, or multi-component feature that needs a design spec and user alignment first",
        deep_bug_diagnosis: "Complex bug, race condition, or regression requiring root-cause reproduction before changing code"
      }
    },
    recommended_model_tier: {
      type: "choice",
      instructions: "What LLM compute tier is optimal for executing this task cost-effectively?",
      criteria: {
        fast_lightweight: "Routine boilerplate, formatting, simple file lookup, or straightforward wiring (Flash / Haiku tier)",
        balanced_coding: "Standard feature implementation, component creation, or unit test authoring (Sonnet / Pro tier)",
        deep_reasoning_flagship: "Complex system architecture, subtle security audit, concurrency debugging, or multi-module redesign (Opus / Argon High tier)"
      }
    },
    requires_security_review: {
      type: "noul",
      instructions:
        "Does this task touch authentication, authorization, untrusted user input, database queries, file uploads, shell execution, secrets, or network APIs?"
    },
    requires_ui_ux_design_system: {
      type: "noul",
      instructions:
        "Does this task involve frontend UI components, layouts, styling, or web animations (GSAP/CSS)?"
    },
    ambiguity_needs_user_question: {
      type: "noul",
      instructions:
        "Are the requirements underspecified such that the agent should ask a clarifying question before writing code?"
    },
    complexity_score: {
      type: "score",
      instructions: "Rate the technical complexity of the task from 1 (trivial) to 5 (highly complex architectural change)."
    }
  };
}

export const DEFAULT_DEVELOPER_PROFILE = {
  architecture: "Prefer deep modules with small clean interfaces, TypeScript/Node.js or Python best practices, DRY, YAGNI, and deterministic tests.",
  security: "Security-first by default: runtime input validation (Zod/Pydantic), parameterized queries, least privilege, no secret leaks.",
  frontend: "High-craft UI/UX (Impeccable/Taste/UI-UX-Pro-Max), 60fps GPU-accelerated GSAP animations (transform x/y/scale, useGSAP, quickTo).",
  workflow: "Autonomous execution preferred for reversible technical/engineering choices; only interrupt the human for irreversible actions, external credentials/billing, or genuine product ambiguity."
};

export function buildAutopilotProxyQuestions(
  options: Record<string, string>
): Record<string, JevQuestion> {
  return {
    selected_option: {
      type: "choice",
      instructions:
        "Acting as the senior developer's calibrated digital twin, select the single best option that maximizes engineering quality, security, and maintainability for this project.",
      criteria: options
    },
    is_reversible_technical_choice: {
      type: "noul",
      instructions:
        "Is this a technical, architectural, or implementation decision that can be safely decided autonomously and reversed via git if needed (as opposed to an irreversible destructive action)?"
    },
    requires_private_business_or_human_taste: {
      type: "noul",
      instructions:
        "Does answering this question genuinely require private business logic, billing/paid API approval, personal credentials, or subjective product goals that cannot be inferred from engineering best practices and the workspace context?"
    },
    alignment_strength: {
      type: "score",
      instructions:
        "How strongly and unambiguously does the winning option outperform the alternatives according to the developer profile and software engineering standards?",
      criteria: [
        "1: Complete tie / pure guess",
        "2: Slight preference but high ambiguity",
        "3: Moderate engineering advantage",
        "4: Clear technical winner",
        "5: Overwhelmingly superior standard practice"
      ]
    }
  };
}
