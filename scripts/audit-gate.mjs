#!/usr/bin/env node
// CI gate for production dependency advisories.
// Fails on any advisory at or above --level (default: moderate) unless it is listed in
// .github/audit-allowlist.json with a reason and an unexpired date. Expired entries fail too.
// Run through npm so the npm CLI can be invoked without a shell: `npm run audit:gate`.
import { execFile } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const ALLOWLIST = path.join(ROOT, ".github", "audit-allowlist.json");
const RANK = { info: 0, low: 1, moderate: 2, high: 3, critical: 4 };

function argValue(flag, fallback) {
  const i = process.argv.indexOf(flag);
  return i !== -1 && process.argv[i + 1] ? process.argv[i + 1] : fallback;
}

function runAudit() {
  const npmCli = process.env.npm_execpath;
  if (!npmCli || !fs.existsSync(npmCli)) {
    throw new Error("npm_execpath is not set; run this through `npm run audit:gate`.");
  }
  return new Promise((resolve, reject) => {
    execFile(
      process.execPath,
      [npmCli, "audit", "--omit=dev", "--json"],
      { cwd: ROOT, maxBuffer: 32 * 1024 * 1024, timeout: 120_000, shell: false },
      (err, stdout) => {
        // npm audit exits non-zero when it finds anything; only a missing/invalid report is an error.
        try {
          resolve(JSON.parse(stdout));
        } catch {
          reject(new Error(`npm audit produced no JSON report${err ? `: ${err.message}` : ""}`));
        }
      }
    );
  });
}

/** Collects unique advisories ({ id, package, severity, title, url }) from an npm audit v2 report. */
export function collectAdvisories(report) {
  if (report?.error) throw new Error(`npm audit failed: ${report.error.summary ?? JSON.stringify(report.error)}`);
  const found = new Map();
  for (const vuln of Object.values(report?.vulnerabilities ?? {})) {
    for (const via of vuln.via ?? []) {
      if (typeof via !== "object" || !via) continue;
      const id = String(via.url ?? via.source ?? "").split("/").pop();
      if (!id) continue;
      found.set(id, { id, package: via.name, severity: via.severity, title: via.title, url: via.url });
    }
  }
  return [...found.values()];
}

/** Pure decision: which advisories block, which allowlist entries expired, which are stale. */
export function evaluate(advisories, allow, { level, today }) {
  const min = RANK[level];
  if (min === undefined) throw new Error(`Unknown --level ${level}`);
  const byId = new Map(allow.map((a) => [a.id, a]));
  const blocking = [];
  const accepted = [];
  for (const adv of advisories) {
    if ((RANK[adv.severity] ?? RANK.critical) < min) continue;
    const entry = byId.get(adv.id);
    if (!entry) blocking.push({ ...adv, why: "not allowlisted" });
    else if (!entry.reason || !/^\d{4}-\d{2}-\d{2}$/.test(entry.expires ?? "")) blocking.push({ ...adv, why: "allowlist entry needs reason and expires (YYYY-MM-DD)" });
    else if (entry.expires < today) blocking.push({ ...adv, why: `allowlist entry expired on ${entry.expires}` });
    else accepted.push({ ...adv, expires: entry.expires });
  }
  const present = new Set(advisories.map((a) => a.id));
  const stale = allow.filter((a) => !present.has(a.id)).map((a) => a.id);
  return { blocking, accepted, stale };
}

async function main() {
  const level = argValue("--level", "moderate");
  const today = argValue("--today", new Date().toISOString().slice(0, 10));
  const allow = JSON.parse(fs.readFileSync(ALLOWLIST, "utf8")).allow ?? [];
  const { blocking, accepted, stale } = evaluate(collectAdvisories(await runAudit()), allow, { level, today });

  for (const a of accepted) console.log(`ACCEPTED ${a.id} (${a.severity}, ${a.package}) until ${a.expires}: ${a.title}`);
  for (const id of stale) console.log(`NOTICE   ${id} is no longer reported; remove it from .github/audit-allowlist.json`);
  for (const b of blocking) console.error(`BLOCKED  ${b.id} (${b.severity}, ${b.package}) ${b.why}: ${b.title} ${b.url ?? ""}`);

  if (blocking.length > 0) {
    console.error(`\nProduction audit gate failed: ${blocking.length} advisory(ies) at or above "${level}".`);
    process.exit(1);
  }
  console.log(`Production audit gate passed (level "${level}", ${accepted.length} temporarily accepted).`);
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().catch((err) => {
    console.error(err instanceof Error ? err.message : err);
    process.exit(1);
  });
}
