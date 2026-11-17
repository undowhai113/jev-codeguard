import test from "node:test";
import assert from "node:assert/strict";
import {
  detectCodeStack,
  buildSkillAuditQuestions,
  extractSkillRemediation,
  auditCodeWithSkills,
  resolveSkillsDir
} from "../src/core/skill-auditor.js";
import { JevClient } from "../src/core/jev-client.js";
import type { JevResponse } from "../src/core/types.js";

test("detectCodeStack accurately identifies Next.js, FastAPI, Golang, Express, and GSAP stacks", () => {
  assert.equal(
    detectCodeStack("import { NextRequest, NextResponse } from 'next/server';", "app/api/user/route.ts"),
    "nextjs"
  );
  assert.equal(
    detectCodeStack("from fastapi import FastAPI, Depends\napp = FastAPI()", "main.py"),
    "fastapi"
  );
  assert.equal(
    detectCodeStack("package main\nimport \"net/http\"", "server.go"),
    "golang"
  );
  assert.equal(
    detectCodeStack("import gsap from 'gsap';\ngsap.to('.box', { top: 100 });", "HeroAnim.tsx"),
    "gsap"
  );
});

test("extractSkillRemediation reads real local skill references when present and provides targeted excerpts", () => {
  const skillsDir = resolveSkillsDir();
  const excerpts = extractSkillRemediation(skillsDir, "nextjs", [
    { vector: "ssrf_or_open_redirect", probability: 0.91 },
    { vector: "xss_or_unsafe_html", probability: 0.78 }
  ]);

  assert.equal(excerpts.length, 2);
  assert.equal(excerpts[0].vector, "ssrf_or_open_redirect");
  assert.ok(excerpts[0].skillFile.includes("nextjs") || excerpts[0].skillFile.includes("security"));
  assert.ok(excerpts[0].excerpt.length > 40);
});

test("auditCodeWithSkills runs parallel System-1 rubric and triggers Lazy Skill Escalation on high-probability risks", async () => {
  const mockFetch: typeof fetch = async () => {
    const payload: JevResponse = {
      model: "jev-1.14.0",
      answers: {
        unvalidated_input: { type: "noul", noul: 0.88 },
        broken_authz_or_idor: { type: "noul", noul: 0.12 },
        injection_sql_cmd_path: { type: "noul", noul: 0.05 },
        xss_or_unsafe_html: { type: "noul", noul: 0.04 },
        ssrf_or_open_redirect: { type: "noul", noul: 0.92 },
        csrf_or_cookie_flaw: { type: "noul", noul: 0.10 },
        secrets_or_env_leak: { type: "noul", noul: 0.02 },
        cache_or_state_leak: { type: "noul", noul: 0.08 },
        dos_or_unbounded_resource: { type: "noul", noul: 0.15 },
        shallow_module_or_arch_flaw: { type: "noul", noul: 0.20 },
        overall_security_score: {
          type: "score",
          score: 1.8,
          probabilities: { "1": 0.4, "2": 0.4, "3": 0.2 }
        },
        audit_verdict: {
          type: "choice",
          selected: "block_and_fix",
          probabilities: { clean_pass: 0.02, review_warnings: 0.13, block_and_fix: 0.85 }
        }
      },
      usage: { input_tokens: 310, output_tokens: 45, cost: 0.000013 }
    };
    return new Response(JSON.stringify(payload), { status: 200 });
  };

  const client = new JevClient({ apiKey: "jev_test_skill", fetchImpl: mockFetch });
  const result = await auditCodeWithSkills(client, {
    code: `
      import { NextRequest, NextResponse } from "next/server";
      export async function GET(req: NextRequest) {
        const target = req.nextUrl.searchParams.get("url")!;
        const res = await fetch(target);
        return NextResponse.json(await res.json());
      }
    `,
    filePath: "app/api/proxy/route.ts",
    violationThreshold: 0.55
  });

  assert.equal(result.stack, "nextjs");
  assert.equal(result.verdict, "BLOCK");
  assert.equal(result.violatedVectors.length, 2);
  assert.equal(result.violatedVectors[0].vector, "ssrf_or_open_redirect");
  assert.equal(result.violatedVectors[1].vector, "unvalidated_input");
  assert.ok(result.skillExcerpts.length >= 2);
  assert.ok(buildSkillAuditQuestions("gsap").gsap_layout_thrashing_or_cleanup);
  assert.match(result.summary, /^BLOCK: security vector\(s\) ssrf_or_open_redirect \(0\.92\)/);
});

function auditClient(overrides: Record<string, JevResponse["answers"][string]>): JevClient {
  const base: JevResponse["answers"] = {
    unvalidated_input: { type: "noul", noul: 0.1 },
    broken_authz_or_idor: { type: "noul", noul: 0.1 },
    injection_sql_cmd_path: { type: "noul", noul: 0.05 },
    xss_or_unsafe_html: { type: "noul", noul: 0.05 },
    ssrf_or_open_redirect: { type: "noul", noul: 0.05 },
    csrf_or_cookie_flaw: { type: "noul", noul: 0.05 },
    secrets_or_env_leak: { type: "noul", noul: 0.05 },
    cache_or_state_leak: { type: "noul", noul: 0.05 },
    dos_or_unbounded_resource: { type: "noul", noul: 0.1 },
    shallow_module_or_arch_flaw: { type: "noul", noul: 0.2 },
    gsap_layout_thrashing_or_cleanup: { type: "noul", noul: 0.1 },
    overall_security_score: { type: "score", score: 4.2, probabilities: {} },
    audit_verdict: { type: "choice", selected: "clean_pass", probabilities: { clean_pass: 0.9 } }
  };
  const answers = { ...base, ...overrides };
  const fetchImpl: typeof fetch = async () =>
    new Response(JSON.stringify({ model: "jev-test", answers } satisfies JevResponse), { status: 200 });
  return new JevClient({ apiKey: "jev_test_skill", fetchImpl });
}

test("audit summary never says 'passed' for a low score without vectors, and GSAP only when checked", async () => {
  // Real #191: 0 violations, score 2.70, model voted block_and_fix -> was BLOCK + "All ... checks passed".
  const lowScore = await auditCodeWithSkills(
    auditClient({
      overall_security_score: { type: "score", score: 2.7, probabilities: {} },
      audit_verdict: { type: "choice", selected: "block_and_fix", probabilities: { block_and_fix: 0.7 } }
    }),
    { code: "def recover():\n    pass\n", filePath: "scripts/lab/recover-proxmox-node.py" }
  );
  assert.equal(lowScore.stack, "general");
  assert.equal(lowScore.violatedVectors.length, 0);
  assert.equal(lowScore.verdict, "ASK_USER");
  assert.doesNotMatch(lowScore.summary, /passed/i);
  assert.match(lowScore.summary, /overall score is 2\.70\/5, model voted block_and_fix; review manually/);

  const cleanGeneral = await auditCodeWithSkills(auditClient({}), {
    code: "def add(a, b):\n    return a + b\n",
    filePath: "scripts/util.py"
  });
  assert.equal(cleanGeneral.verdict, "ALLOW");
  assert.doesNotMatch(cleanGeneral.summary, /GSAP/);
  assert.match(cleanGeneral.summary, /9 security \+ 1 architecture/);

  const cleanReact = await auditCodeWithSkills(auditClient({}), {
    code: "export function Card() { const [x] = useState(0); return x; }",
    filePath: "src/Card.tsx"
  });
  assert.equal(cleanReact.stack, "react");
  assert.match(cleanReact.summary, /1 GSAP animation/);
});

test("a GSAP or architecture finding alone never blocks (misspelled filter key regression)", async () => {
  const res = await auditCodeWithSkills(
    auditClient({
      gsap_layout_thrashing_or_cleanup: { type: "noul", noul: 0.9 },
      shallow_module_or_arch_flaw: { type: "noul", noul: 0.85 }
    }),
    {
      code: "import gsap from 'gsap';\nexport function Hero() { useEffect(() => { gsap.to('.box', { top: 100 }); }); }",
      filePath: "src/Hero.tsx"
    }
  );
  assert.equal(res.stack, "gsap");
  assert.equal(res.verdict, "ALLOW");
  assert.deepEqual(
    res.violatedVectors.map((v) => v.vector).sort(),
    ["gsap_layout_thrashing_or_cleanup", "shallow_module_or_arch_flaw"]
  );
  assert.match(res.summary, /^ALLOW with non-blocking findings/);
});
