# Changelog

All notable changes to `mcp-jev` are documented in this file.

## [1.0.0] - 2026-11-17

### Added
- **9 MCP Tools (`mcp-jev serve`):** `jev_guard_action`, `jev_verify_diff`, `jev_audit_code`, `jev_autopilot_decide`, `jev_prune_context`, `jev_classify_batch`, `jev_route_task`, `jev_decide`, and `jev_stats`.
- **Literal Command-Shape Gate (`src/core/command-shape.ts`):** Rejects natural-language prose passed to `jev_guard_action` (`exact_command`) and `jev-gate` so agents cannot self-describe risky commands as "read-only".
- **Calibrated Policy Engine (`src/core/policy-config.ts` & `policy-engine.ts`):** Frozen `JEV_POLICY` thresholds calibrated across 330+ multi-agent events; separates concrete security/regression blockers from spec-alignment warnings; enforces opt-in `JEV_AUTOPILOT=1` with a 15-minute cross-process guard escalation lock.
- **Deep Context & Hybrid Open-Source AST Engine (`src/core/context-enricher.ts` & `hybrid-ast-engine.ts`):** Enriches evaluations with `ts-morph` and Python `ast` symbol skeletons, `oxlint` (Rust JS/TS) and `ruff` (Rust Python + Bandit security) diagnostics, `codegraph` affected-test discovery, Spec-to-Diff alignment matrices, cross-file contracts, reverse dependents, and untracked new-file diff synthesis.
- **Skill-Backed Security & Quality Auditor (`src/core/skill-auditor.ts`):** Evaluates 9 OWASP/AppSec vectors + deep-module architecture + 60fps GSAP animation rules with Lazy `SKILL.md` Escalation across `nextjs`, `express`, `react`, `vue`, `frontend`, `fastapi`, `django`, `flask`, `golang`, and `gsap`.
- **Bilingual (`EN` / `VI`) Live Radar Portal (`src/dashboard/server.ts`):** Local SSE dashboard on `127.0.0.1:4399` with multi-agent filtering, probability visualizations, and persistent Human-in-the-Loop Project Brain rules (`~/.mcp-jev/projects/<workspace>.json`).
- **Zero-Trust `PreToolUse` Hook Firewall (`jev-gate`):** Deterministic CLI hook interceptor for Claude Code and Cursor (`0` allow, `ask`, `2` block with remediation).
- **Atomic Multi-Process Event Ledger (`src/core/event-log.ts`):** Lockfile-guarded `5 MiB` log rotation (`events.jsonl` $\rightarrow$ `events.1.jsonl`) and reverse-chunk tail reader.

### Security
- Eliminated all `shell: true` child-process invocations across Windows, macOS, and Linux.
- Added canonical `realpathSync` workspace containment (`isWithinWorkspaceBoundary`) and sensitive-file redaction (`.env`, `*.pem`, `*.key`, SSH keys, `config.json`).
- Hardened `127.0.0.1:4399` Radar Portal with `Host` DNS-rebinding checks, `Content-Security-Policy`, and per-boot `24-byte` cryptographic CSRF tokens (`crypto.timingSafeEqual`).
- Restricted `~/.mcp-jev/config.json` permissions to `0600`.
