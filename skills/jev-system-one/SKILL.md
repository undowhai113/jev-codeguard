---
name: jev-system-one
description: Use TypeSafe AI's Jev (System-1 Decision Engine) via `mcp-jev` for ~150ms calibrated probability decisions, zero-token local `git diff` verification, Skill-Backed Security & GSAP/Architecture auditing, out-of-context file/skill pruning, and multi-agent task routing.
---

# Jev System-One Decision & Guardrail Workflow (`mcp-jev`)

## Overview

You are a **System-2** reasoning agent paired with **Jev** (`mcp-jev`), a lightning-fast (~150ms, $0.042/1M input tokens, free output) **System-1** calibrated probability engine trained with Reinforcement Learning for Calibrated Decisions (RLCD).

Instead of wasting your context window or relying on uncalibrated self-assessment, delegate binary checks, security/skill audits, file pruning, and diff verification to `mcp-jev`.

---

## When to Invoke Each `mcp-jev` Tool

### 0. Multiple-Choice Technical Questions $\rightarrow$ `jev_autopilot_decide` (Human-Proxy Recommender)
- Before asking the user to choose between technical options (architecture, library, test seam, folder layout), call `jev_autopilot_decide` first for a calibrated decision.
- Autopilot is **disabled by default** (`ASK_HUMAN`). Users can enable it anytime via `JEV_AUTOPILOT=1`, `jev-codeguard setup --autopilot`, `jev-codeguard autopilot-mode on`, or the **Autopilot toggle** on the Live Radar Portal (`http://127.0.0.1:4399`).
  - `mode === "AUTOPILOT_PROCEED"` (enabled, $P \ge 0.65$, reversible technical choice): proceed with `selectedOption` without interrupting the user; state the choice in one line and still ask the user if new risk, cost, or scope appears.
  - `mode === "ASK_HUMAN"`: ask the user, listing `selectedOption` first as `(Recommended)`.
- Never use `jev_autopilot_decide` to get past a `jev_guard_action` `ASK_USER`/`BLOCK`. Within 15 minutes of such a guard verdict in the same workspace it always returns `ASK_HUMAN`.
- Product scope, deliverable size, credentials, billing, and anything the user already asked to confirm are the user's decisions, not autopilot's.

### 1. Start of a Complex Task $\rightarrow$ `jev_route_task` & `jev_prune_context`
- Call **`jev_route_task`** when given a broad feature or bug to get calibrated probabilities on:
  - Optimal strategy (`direct_edit`, `tdd_red_green`, `parallel_subagents`, `brainstorm_spec_first`, `deep_bug_diagnosis`)
  - Whether security skills or UI/UX/GSAP skills are required
- Call **`jev_prune_context`** when you have >10 candidate files, search results, or skills:
  - Pass up to 100 `{ id, summary }` items. Jev scores all 100 in **a single ~150ms parallel pass** and returns only items with $P(\text{relevant}) \ge 0.60$, keeping noise out of your context window.

### 2. Before Risky Commands or Destructive Refactors $\rightarrow$ `jev_guard_action`
- Before running shell commands that delete files, mutate git history, run database migrations, or touch external services, call **`jev_guard_action`**.
- Pass the **literal command line you will run** in `exact_command` (the same string you will execute, e.g. `git add -- docs/a.md; git commit -m "docs: x"`). Put the explanation, scope, and any user authorization in `context`. A prose description in `exact_command` is not scored and returns `ASK_USER`.
- If you run several commands, guard the risky one(s) individually, each with its exact text.
- Respect the returned verdict:
  - `ALLOW`: Execute exactly the command that was guarded.
  - `ASK_USER`: Ask the user for confirmation first (an earlier general instruction is not a confirmation of this specific command; do not ask `jev_autopilot_decide` instead).
  - `BLOCK`: Abort and follow the returned `remediation` steps.

### 3. After Writing Backend, Frontend, or Animation Code $\rightarrow$ `jev_audit_code`
- Call **`jev_audit_code`** (you can omit `code` to automatically audit the local `git diff` at zero token cost!).
- **Lazy Skill Escalation (with Bundled Skills):**
  - Jev scores 10+ vectors compiled from your installed skills or the vendored Apache-2.0/MIT skill library bundled inside `jev-codeguard` (`security-best-practices`, `gsap-performance`, `codebase-design`).
  - If all vectors pass ($P < 0.55$), you do **not** need to load 1,000-line skill reference files into your context.
  - If any vector exceeds $P \ge 0.55$, `jev_audit_code` automatically extracts the exact remediation rules from your local skill (or the bundled fallback inside `jev-codeguard`) for `nextjs`, `express`, `fastapi`, `django`, `golang`, `gsap`, etc. so you can fix the issue immediately.

### 4. Before Claiming Completion or Committing $\rightarrow$ `jev_verify_diff`
- Call **`jev_verify_diff`** with the user's original request as `spec` and optional `test_output` (leave `git_diff` empty so `jev-codeguard` collects `git diff HEAD` locally with zero token overhead). Pass `working_directory` so the right repository is read.
- Respect the returned verdict:
  - `ALLOW`: clean.
  - `ASK_USER` (warning): spec alignment is uncertain or tests look missing. Tell the user which parts are uncertain when you report completion. Do **not** rewrite the `spec` to match the diff and re-run until it passes.
  - `BLOCK`: elevated regression or security risk in the added code. Fix it (use `jev_audit_code` for security) before declaring completion.
