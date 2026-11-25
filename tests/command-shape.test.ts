import test from "node:test";
import assert from "node:assert/strict";
import { assessCommandShape } from "../src/core/command-shape.js";

// Guard inputs Codex actually sent (events-snapshot.jsonl) — descriptions, not commands.
const PROSE_FROM_LOG = [
  "Commit only four documentation files: docs/memory/CURRENT.md, docs/memory/WORKBOARD.md, docs/memory/logs/2026-10-25.md, docs/memory/handoffs/windows-console-ai-20261025.md. Message docs(spec): define Windows console and AI handoff.",
  "Commit exactly4reviewmemorydocs CURRENT.md WORKBOARD.md logs/2026-10-27.md handoffs/assessment-ai-auto-publication-20261026.md with docs(review) conventionalcommit; no implementation change.",
  "Read-only SSH surveys using ops-windows alias temporary HostName198.51.100.22 strict host-key and batch mode; PowerShell Get-CimInstance/Get-BitLockerVolume(selected ProtectionStatus only), bcdedit /enum only",
  "One bounded Windows command: chkdsk.exe E: /markclean. No /f,/r,/x,/freeorphanedchains, no yes-to-prompts, no reboot/scheduling.",
  "git fetch current PR43 and develop into dedicated review refs, no checkout or branch mutation; gh read PRcomments andCIlogs",
  "gh issue comment 71 --repo acme-org/ops-dashboard --body-file ops-oct26-issue71-comment.md, then gh pr comment 50 --repo acme-org/ops-dashboard --body-file ops-oct26-pr50-comment.md",
  "node --test tests/lobby-acceptance-guard.test.mjs tests/lobby-view-preference.test.mjs and run isolated current-helper WebSocket regression in headless Edge outside sandbox",
  "Approve PR50 at exact commit06d17fc2a2e4d1d9cb1a3f0e19fc7f1e4ca4d126, then gh pr merge50 --admin --squash"
];

// Commands that were really executed (Codex exec_command / Antigravity run_command).
const REAL_COMMANDS = [
  "npm test",
  "chkdsk.exe E: /markclean",
  'git add -- docs/memory/CURRENT.md docs/memory/WORKBOARD.md docs/memory/logs/2026-10-26.md; git commit -m "docs(review): record revision three proof admission findings"',
  ".\\backend\\.venv\\Scripts\\python.exe scripts\\lab\\run-attack-defense-pilot-a0-20261029.py --run-id codex-r2-20261030-4bc3 --output-dir .runtime\\codex-pilot --port-base 38280",
  "gh api repos/acme-org/ops-dashboard/issues/74/comments --jq '.[] | {author:.user.login,html_url,body}'",
  "Get-Content -LiteralPath 'docs/memory/handoffs/lobby-live-acceptance-20261025.md' -First 16; Get-Content -LiteralPath 'docs/memory/logs/2026-10-25.md' -Tail 6",
  "$expectedHead='6ec648ba97fa0f4d5ae9d52b49e3f1572b767522'\n$actualHead=git rev-parse HEAD\nif ($actualHead -ne $expectedHead) { throw 'Review head changed; refusing commit' }",
  "@'\nimport json,pathlib\nfor name in ['a.json','b.json']:\n    print(json.dumps({'name': name, 'exists': pathlib.Path(name).exists()}))\n'@ | backend/.venv/Scripts/python.exe -",
  "$script = @'\nconst { PrismaClient } = require('@prisma/client');\nconst prisma = new PrismaClient();\n// read the first lab and print it to the console for review\n'@\nnode -e $script",
  "$pairs=@{}; Get-Content .env | ForEach-Object { if($_ -match '^(\\w+)=(.*)$'){ $pairs[$matches[1]]=$matches[2].Trim().Trim('\"').Trim(\"'\") } }",
  "# Also inspect the SVG of the tree and the icons from the luxe set\nInvoke-WebRequest -Uri \"https://api.iconify.design/x.svg\" -UseBasicParsing",
  "'SELECT count(*) FILTER (WHERE password IS NOT NULL AND password<>'''') AS legacy FROM staff;' | ssh -o BatchMode=yes deploy@host 'psql -At'",
  "for f in *.md; do echo $f; done",
  "apt-get install -y curl wget git vim htop jq"
];

test("assessCommandShape flags prose descriptions that agents sent as commands", () => {
  for (const text of PROSE_FROM_LOG) {
    const shape = assessCommandShape(text);
    assert.equal(shape.looksLikeProse, true, `expected prose: ${text.slice(0, 80)}`);
    assert.ok(shape.signals.length > 0);
  }
  assert.deepEqual(assessCommandShape("   ").signals, ["empty"]);
});

test("assessCommandShape flags Vietnamese intent prose while accepting quoted Vietnamese paths", () => {
  const vnProse = [
    "Em chỉ dọn file rác thôi ạ",
    "em chỉ dọn file rác thôi ạ",
    "Chỉ xóa các file tạm không cần thiết trong dự án này thôi",
    "Tôi sẽ chạy lệnh cập nhật cấu hình bảo mật cho hệ thống"
  ];
  for (const text of vnProse) {
    const shape = assessCommandShape(text);
    assert.equal(shape.looksLikeProse, true, `expected Vietnamese prose: ${text}`);
  }

  const vnCommands = [
    'git commit -m "Em chỉ dọn file rác thôi ạ"',
    'cat "tài liệu bảo mật.md"',
    "ls -la"
  ];
  for (const cmd of vnCommands) {
    const shape = assessCommandShape(cmd);
    assert.equal(shape.looksLikeProse, false, `expected literal command: ${cmd}`);
  }
});

test("assessCommandShape accepts literal commands, ignoring quoted strings, here-strings and comments", () => {
  for (const cmd of REAL_COMMANDS) {
    const shape = assessCommandShape(cmd);
    assert.equal(
      shape.looksLikeProse,
      false,
      `expected literal command (${shape.signals.join(",")}): ${cmd.slice(0, 80)}`
    );
  }
});
