#!/usr/bin/env node
// Re-vendors the third-party remediation skills bundled in skills/vendor/ from their
// upstream repositories at pinned commits, verbatim, together with each upstream license.
// Usage: node scripts/vendor-skills.mjs   (then review `git diff skills/vendor`)
import { createHash } from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const VENDOR_DIR = path.join(ROOT, "skills", "vendor");

const SECURITY_REFERENCES = [
  "golang-general-backend-security.md",
  "javascript-express-web-server-security.md",
  "javascript-general-web-frontend-security.md",
  "javascript-jquery-web-frontend-security.md",
  "javascript-typescript-nextjs-web-server-security.md",
  "javascript-typescript-react-web-frontend-security.md",
  "javascript-typescript-vue-web-frontend-security.md",
  "python-django-web-server-security.md",
  "python-fastapi-web-server-security.md",
  "python-flask-web-server-security.md"
];

export const SOURCES = [
  {
    skill: "security-best-practices",
    repo: "openai/skills",
    commit: "49f948faa9258a0c61caceaf225e179651397431",
    license: "Apache-2.0",
    copyright: "OpenAI",
    files: [
      ["skills/.curated/security-best-practices/SKILL.md", "SKILL.md"],
      ["skills/.curated/security-best-practices/LICENSE.txt", "LICENSE.txt"],
      ...SECURITY_REFERENCES.map((f) => [
        `skills/.curated/security-best-practices/references/${f}`,
        `references/${f}`
      ])
    ]
  },
  {
    skill: "gsap-performance",
    repo: "greensock/gsap-skills",
    commit: "aed9cfd3277740755f6bfc1155c7aa645403b760",
    license: "MIT",
    copyright: "Copyright (c) 2026 GreenSock",
    files: [
      ["skills/gsap-performance/SKILL.md", "SKILL.md"],
      ["LICENSE", "LICENSE"]
    ]
  },
  {
    skill: "codebase-design",
    repo: "mattpocock/skills",
    commit: "5863806dd4e15c63174bee4e7515a4256792ecfa",
    license: "MIT",
    copyright: "Copyright (c) 2026 Matt Pocock",
    files: [
      ["skills/engineering/codebase-design/SKILL.md", "SKILL.md"],
      ["skills/engineering/codebase-design/DEEPENING.md", "DEEPENING.md"],
      ["skills/engineering/codebase-design/DESIGN-IT-TWICE.md", "DESIGN-IT-TWICE.md"],
      ["LICENSE", "LICENSE"]
    ]
  }
];

const MAX_FILE_BYTES = 256 * 1024;

async function download(repo, commit, srcPath) {
  if (!/^[0-9a-f]{40}$/.test(commit)) throw new Error(`Commit must be a full SHA: ${commit}`);
  const url = `https://raw.githubusercontent.com/${repo}/${commit}/${srcPath}`;
  const res = await fetch(url, { redirect: "error", signal: AbortSignal.timeout(20_000) });
  if (!res.ok) throw new Error(`HTTP ${res.status} for ${url}`);
  const buf = Buffer.from(await res.arrayBuffer());
  if (buf.length === 0 || buf.length > MAX_FILE_BYTES) {
    throw new Error(`Unexpected size ${buf.length} bytes for ${url}`);
  }
  return buf;
}

function safeTarget(skillDir, relPath) {
  const target = path.resolve(skillDir, relPath);
  if (!target.startsWith(skillDir + path.sep)) throw new Error(`Refusing path outside vendor dir: ${relPath}`);
  return target;
}

async function main() {
  const manifest = { generatedBy: "scripts/vendor-skills.mjs", sources: [] };
  for (const src of SOURCES) {
    const skillDir = path.join(VENDOR_DIR, src.skill);
    fs.rmSync(skillDir, { recursive: true, force: true });
    const files = [];
    for (const [srcPath, destRel] of src.files) {
      const buf = await download(src.repo, src.commit, srcPath);
      const dest = safeTarget(skillDir, destRel);
      fs.mkdirSync(path.dirname(dest), { recursive: true });
      fs.writeFileSync(dest, buf);
      files.push({ path: destRel, upstream: srcPath, sha256: createHash("sha256").update(buf).digest("hex") });
      console.log(`  ${src.skill}/${destRel} (${buf.length} B)`);
    }
    manifest.sources.push({
      skill: src.skill,
      repo: `https://github.com/${src.repo}`,
      commit: src.commit,
      license: src.license,
      copyright: src.copyright,
      files
    });
  }
  fs.writeFileSync(path.join(VENDOR_DIR, "manifest.json"), `${JSON.stringify(manifest, null, 2)}\n`);
  console.log(`Vendored ${manifest.sources.length} skills into ${path.relative(ROOT, VENDOR_DIR)}`);
}

main().catch((err) => {
  console.error(err instanceof Error ? err.message : err);
  process.exit(1);
});
