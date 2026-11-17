# Security Policy

## Supported Versions

| Version | Supported |
| :--- | :--- |
| `1.0.x` | ✅ Supported |

## Security Architecture & Trust Boundaries

`mcp-jev` sits directly in the execution loop of autonomous coding agents (Claude Code, OpenAI Codex, Cursor, Google Antigravity / Gemini). Security is treated as a first-class invariant:

1. **Zero Shell Interpolation (`shell: false`):** All local child processes (`git`, `oxlint`, `ruff`, `codegraph`, `python`) are invoked via `execFileSync` / `spawn` argument arrays with `shell: false` across Windows, macOS, and Linux.
2. **Canonical Workspace Boundaries:** File inspection (`jev_audit_code` and `extractReferencedDocsAndFiles`) enforces `fs.realpathSync` containment (`isWithinWorkspaceBoundary`) so `../` path traversal or symlink escapes outside the active workspace are rejected.
3. **Automatic Secret File Redaction:** Files matching `.env`, `.env.*` (excluding `.env.example`/`.sample`/`.template`), `*.pem`, `*.key`, `*.p12`, `*.pfx`, `id_rsa`, `id_ed25519`, `credentials.json`, `~/.ssh/*`, `~/.aws/*`, and `~/.mcp-jev/config.json` are blocked from ever being read or transmitted.
4. **Localhost Dashboard Isolation (`127.0.0.1`):** The Live Radar Portal binds exclusively to `127.0.0.1`, validates the `Host` header against DNS-rebinding attacks, enforces `Content-Security-Policy` and `X-Frame-Options: DENY`, and requires a per-boot `24-byte` cryptographic CSRF token (`crypto.timingSafeEqual`) on all mutating `POST` / `DELETE` routes.
5. **Anti-Gaming Guardrails:**
   - `jev_guard_action` rejects natural-language prose descriptions (`assessCommandShape`) so agents must submit the verbatim command string they intend to run.
   - `jev_autopilot_decide` is opt-in (`JEV_AUTOPILOT=1`) and locks to `ASK_HUMAN` for 15 minutes across processes whenever `jev_guard_action` returns `ASK_USER` or `BLOCK` in the same workspace.

## What Data Leaves Your Machine?

- **Sent over HTTPS (`TLS`) to `https://api.typesafe.ai/v1/jev`:** Only the bounded evaluation payload (command string, budgeted `git diff`, or non-sensitive source snippet) when an MCP tool or `jev-gate` hook is invoked.
- **Stored 100% locally (`~/.mcp-jev/`):** Your API key (`config.json`, mode `0600`), rotated session event ledger (`events.jsonl`, `5 MiB` cap), and Project Brain human-override profiles (`projects/*.json`).

## Reporting a Vulnerability

Please **do not** open a public GitHub issue for security vulnerabilities (such as command-gate bypasses, path-traversal escapes, or localhost CSRF/DNS-rebinding flaws).

Instead, use **GitHub Private Vulnerability Reporting** (`Security` tab $\rightarrow$ `Report a vulnerability`) on this repository. Include:
- Affected version and operating system
- Minimal reproduction payload or test case
- Impact assessment

We aim to acknowledge reports within **48 hours** and ship a verified patch with regression tests promptly.
