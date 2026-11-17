# Contributing to MCP-Jev

Thank you for helping make AI coding agents safer, faster, and better calibrated!

## Development Setup

### Prerequisites
- **Node.js `>= 20.0.0`**
- **npm `>= 10.0.0`**
- *(Optional)* Python 3 + `ruff` (`pip install ruff`) and `@colbymchenry/codegraph` (`npm i -g @colbymchenry/codegraph`) for testing optional static/graph integrations.

### Install, Build & Test

```bash
npm install
npm run build
npm test
```

All tests use Node's built-in `node:test` runner (`dist/tests/*.test.js`) with mocked `fetch` transports — **no live API key is required to run `npm test`**.

## Repository Map

- `src/core/policy-config.ts` — Single frozen source of truth (`JEV_POLICY`) for all calibrated probability thresholds.
- `src/core/policy-engine.ts` — Pure decision logic (`evaluateCommandGate`, `evaluateDiffGate`, `evaluateAutopilotProxy`, `findBlockingGuardEscalation`).
- `src/core/command-shape.ts` — Deterministic detector separating literal shell commands from agent prose summaries.
- `src/core/context-enricher.ts` — Project Brain DNA harvester, Spec-to-Diff matrix, cross-file contract extractor, and workspace/secret file boundary checks.
- `src/core/hybrid-ast-engine.ts` — `ts-morph` + Python `ast` skeleton extraction, `oxlint` & `ruff` static analysis, and `codegraph` dependency intelligence (`shell: false`).
- `src/core/skill-auditor.ts` — Stack detection, 10+ OWASP/Architecture/GSAP rubric vectors, and Lazy `SKILL.md` Escalation.
- `src/mcp/server.ts` — MCP stdio server registering all 9 tools.
- `src/dashboard/server.ts` — Zero-dependency bilingual (`EN` / `VI`) SSE Radar Portal (`http://127.0.0.1:4399`).
- `src/cli/` — `mcp-jev` & `jev-gate` CLI entrypoints and `PreToolUse` hook runner.

## Engineering Rules for Pull Requests

1. **Zero `shell: true`:** Never pass `shell: true` to `execFileSync`, `execFile`, or `spawn`. Resolve binaries or Node entrypoints directly.
2. **Test Isolation:** Tests that emit events or mutate Project Brain profiles MUST isolate `process.env.JEV_EVENTS_FILE` and `HOME` / `USERPROFILE` to `os.tmpdir()` and clean up in `finally`.
3. **Threshold Changes Require Calibration Tests:** Any adjustment to `JEV_POLICY` in `src/core/policy-config.ts` must include a regression case in `tests/policy-calibration.test.ts` explaining the false-positive or false-negative scenario.
4. **No Personal Paths or Secrets:** Never include machine-specific paths (`/Users/<realname>`, `C:\Users\<realname>`), private LAN IPs, or live keys in source files, fixtures, or docs. Use RFC 5737 test IPs (`198.51.100.x`) and generic `acme-*` fixtures.
5. **Pre-Submit Check:** Ensure `npm test`, `npm audit --omit=dev`, and `npm pack --dry-run` all succeed cleanly before opening a PR.
