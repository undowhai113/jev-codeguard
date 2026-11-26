# Changelog

All notable changes to `jev-codeguard` (`mcp-jev`) are documented in this file.

## [1.2.0] - 2026-11-26

### Added
- **Live Human-Proxy Autopilot Toggle (Zero-Restart):**
  - Added `src/core/runtime-config.ts` to persist `autopilot: boolean` cleanly inside `~/.mcp-jev/config.json` (`0600`) without clobbering `apiKey`, with strict precedence (`JEV_AUTOPILOT` env override > `config.json` > safe `false` default).
  - Added `GET /api/settings` & CSRF-protected `POST /api/settings` to the Live Radar Portal (`127.0.0.1:4399`) with real-time SSE `settings_updated` sync across tabs and `409` feedback when locked by `JEV_AUTOPILOT` env var.
  - Added a bilingual (`EN | VI`) **Autopilot Mode** toggle card in the Live Radar sidebar, `Claude Code` & `Cursor` agent filters, and responsive mobile layout (`<= 960px`).
- **Community Setup & CLI Upgrades:**
  - Added `jev-codeguard setup --autopilot` / `--no-autopilot` flags and `jev-codeguard autopilot-mode [on|off|status]` CLI subcommand.
  - Auto-installs companion `SKILL.md` into detected `~/.claude/skills`, `~/.cursor/skills`, `~/.codex/skills`, `~/.agents/skills`, and `~/.gemini/config/skills` folders, and prints a ready-to-paste `CLAUDE.md` / `.cursorrules` / `AGENTS.md` instruction block so agents call `jev_autopilot_decide` before interrupting users.

### Tests
- Added `tests/autopilot-settings.test.ts` covering config precedence, `apiKey` preservation and non-leakage on `/api/settings`, CSRF & `409` env-lock enforcement, `setup --autopilot`, and live zero-restart switching on `McpJevDispatcher.autopilotDecide()`.

## [1.1.1] - 2026-11-25

### Security & Fixes
- Guarded `extractFileHeaderContext`, `extractPostEditHunkScopes`, `extractCrossFileContracts`, and `runFastSyntaxProbe` with `isSafeReadableWorkspaceFile()` (workspace containment + sensitive-file blocklist) and stripped accidentally tracked sensitive file sections from `git diff` in `git-collector.ts`.
- Emitted portable `npx -y jev-codeguard` configs when `setup` runs from `_npx`/`node_modules`, preserved existing `env` keys in `mcp_config.json`, and fixed the missing-key CLI hint.
- Added dedicated `src/cli/gate.ts` bin entrypoint so `jev-gate` works reliably on Windows shims; logged code-write hook audits to the session ledger and forwarded Project Brain rules into `jev-gate`.
- Upgraded `assessCommandShape()` with Unicode letter matching and Vietnamese prose stopwords.
- Added 2 MiB stdin caps, `--port` validation, flag-safe positional parsing, NaN-safe `JEV_TIMEOUT_MS`, bounded telemetry ring buffer, IPv6 `[::1]` dashboard origin, single-quote HTML escaping, `jev_classify_batch` event logging, and `Claude`/`Cursor` agent identity detection.

## [1.1.0] - 2026-11-18

### Added
- **Bundled remediation skills (`skills/vendor/`):** `jev_audit_code` now works out of the box after `npx jev-codeguard setup`. When a vector crosses its threshold and you have not installed the skill yourself, it quotes the bundled copy of OpenAI's `security-best-practices` (Apache-2.0, `SKILL.md` + 10 framework references), GreenSock's `gsap-performance` (MIT) and Matt Pocock's `codebase-design` (MIT). Files are vendored verbatim at pinned commits by `scripts/vendor-skills.mjs`, ship with their upstream licenses, and are listed in `THIRD_PARTY_NOTICES.md`.
- **`skillSource` on every remediation excerpt** (`"local" | "bundled" | "builtin"`) so agents and the Radar can tell where guidance came from.

### Changed
- Skill lookup is now per file: your installed skills win, and any missing file falls back to the bundled copy (previously a partial local install silently dropped to one-line built-in guidance). The bundled directory is resolved from the package location, not the current working directory.
- README and Vietnamese summary describe the real lookup order instead of implying a local `SKILL.md` library is always present.

### Tests
- Added coverage for bundled fallback, local override, built-in last resort, per-stack section resolution, and SHA-256 integrity of every vendored file against `skills/vendor/manifest.json`.

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
