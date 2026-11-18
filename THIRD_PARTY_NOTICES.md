# Third-Party Notices

`jev-codeguard` is released under the [MIT License](LICENSE). It also ships three third-party
agent skills, unmodified, in [`skills/vendor/`](skills/vendor). `jev_audit_code` quotes short
remediation excerpts from them when a risk vector crosses its threshold and you have not
installed your own copy of the same skill.

Each skill keeps its own license, shipped next to it. The exact upstream commit and the SHA-256
of every vendored file are recorded in [`skills/vendor/manifest.json`](skills/vendor/manifest.json),
and the test suite fails if any vendored file is changed. To refresh them from upstream, run
`node scripts/vendor-skills.mjs` and review the diff.

| Bundled skill | Upstream | Pinned commit | License | Copyright |
| --- | --- | --- | --- | --- |
| `security-best-practices` (`SKILL.md` + 10 framework references) | [openai/skills](https://github.com/openai/skills/tree/49f948faa9258a0c61caceaf225e179651397431/skills/.curated/security-best-practices) | `49f948f` | Apache License 2.0 ([`LICENSE.txt`](skills/vendor/security-best-practices/LICENSE.txt)) | OpenAI |
| `gsap-performance` | [greensock/gsap-skills](https://github.com/greensock/gsap-skills/tree/aed9cfd3277740755f6bfc1155c7aa645403b760/skills/gsap-performance) | `aed9cfd` | MIT ([`LICENSE`](skills/vendor/gsap-performance/LICENSE)) | Copyright (c) 2026 GreenSock |
| `codebase-design` (`SKILL.md`, `DEEPENING.md`, `DESIGN-IT-TWICE.md`) | [mattpocock/skills](https://github.com/mattpocock/skills/tree/5863806dd4e15c63174bee4e7515a4256792ecfa/skills/engineering/codebase-design) | `5863806` | MIT ([`LICENSE`](skills/vendor/codebase-design/LICENSE)) | Copyright (c) 2026 Matt Pocock |

Notes:

- The files are redistributed verbatim. `jev-codeguard` does not modify them; it only reads
  sections at runtime.
- The upstream `security-best-practices` skill ships no `NOTICE` file, so Apache 2.0 §4(d)
  adds no further attribution text beyond its license and this notice.
- `jev-codeguard` is not endorsed by, or affiliated with, the authors of these skills.
