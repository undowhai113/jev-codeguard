import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import type { JevClient } from "./jev-client.js";
import { JEV_POLICY } from "./policy-config.js";
import type {
  CodeStack,
  GateVerdict,
  JevAnswer,
  JevQuestion,
  SkillAuditResult,
  SkillRemediationExcerpt
} from "./types.js";

export interface VectorMetadata {
  key: string;
  title: string;
  instructions: string;
  searchKeywords: string[];
  fallbackGuidance: string;
}

export const SECURITY_AUDIT_VECTORS: VectorMetadata[] = [
  {
    key: "unvalidated_input",
    title: "Unvalidated Runtime Input (Missing Schema/Boundary Check)",
    instructions:
      "Does the code consume untrusted input (request params, query, body, headers, cookies, formData, or CLI args) without strict runtime validation and type/length bounds (remembering that TypeScript types vanish at runtime)?",
    searchKeywords: ["Untrusted input", "Input validation", "validation", "request.json", "schema"],
    fallbackGuidance:
      "Validate and bound all untrusted input server-side using a strict schema validator (e.g., Zod/Pydantic) before passing to business logic. Never rely on compile-time TypeScript types as a security boundary."
  },
  {
    key: "broken_authz_or_idor",
    title: "Broken Authentication, Object-Level Authorization (IDOR), or Predictable IDs",
    instructions:
      "Does the code perform state changes or sensitive reads without verifying both authentication AND object-level ownership/authorization (IDOR), or expose sequential auto-incrementing resource IDs?",
    searchKeywords: ["Authorization", "Authentication", "IDOR", "Incrementing IDs", "session"],
    fallbackGuidance:
      "Enforce authentication and object/action-level authorization server-side with least privilege on every route handler and Server Action. Use non-enumerable UUIDs for public resource identifiers."
  },
  {
    key: "injection_sql_cmd_path",
    title: "Injection Risk (SQL/NoSQL, Command Execution, or Path Traversal)",
    instructions:
      "Does the code concatenate untrusted strings into SQL/ORM raw queries, execute shell commands with interpolated arguments (`exec`, `spawn(..., {shell: true})`), or join file paths without canonical boundary verification?",
    searchKeywords: ["Injection", "SQL", "command execution", "path traversal", "File handling"],
    fallbackGuidance:
      "Use parameterized queries and safe process APIs (`execFile` with array arguments, `shell: false`). Canonicalize file paths (`path.resolve`) and verify they remain inside the allowed base directory."
  },
  {
    key: "xss_or_unsafe_html",
    title: "Cross-Site Scripting (XSS) or Unsafe HTML Rendering",
    instructions:
      "Does the code render unescaped or unsanitized HTML (`dangerouslySetInnerHTML`, `v-html`, `innerHTML`, `document.write`, `javascript:` URLs) or weaken Content-Security-Policy (CSP)?",
    searchKeywords: ["XSS", "dangerouslySetInnerHTML", "HTML", "CSP", "sanitize"],
    fallbackGuidance:
      "Rely on framework auto-escaping; if rich HTML is strictly required, sanitize with a maintained allowlist sanitizer (e.g., DOMPurify) and enforce strict CSP headers."
  },
  {
    key: "ssrf_or_open_redirect",
    title: "Server-Side Request Forgery (SSRF) or Open Redirect",
    instructions:
      "Does the server make outbound HTTP/network requests (`fetch`, `axios`, `http.Get`) using a user-controlled URL/host (SSRF), or redirect users (`redirect()`, `res.redirect()`) to an unvalidated external target?",
    searchKeywords: ["SSRF", "Outbound requests", "Redirect", "open redirect"],
    fallbackGuidance:
      "Never pass raw user URLs to server-side `fetch` or `redirect`. Validate against an explicit allowlist of origins/hosts, block private/loopback IP ranges (127.0.0.1, 169.254.169.254, RFC1918), and disable automatic redirect following."
  },
  {
    key: "csrf_or_cookie_flaw",
    title: "CSRF Exposure or Insecure Cookie / Session Configuration",
    instructions:
      "Do state-changing endpoints lack CSRF / Origin verification, or are session cookies configured with weak attributes (missing `httpOnly`, `sameSite`, or permissive CORS `*` with credentials)?",
    searchKeywords: ["CSRF", "cookie", "CORS", "Origin", "sessions"],
    fallbackGuidance:
      "Verify `Origin`/`Host` headers or CSRF tokens on all state-changing routes, set `httpOnly: true` and `sameSite: 'lax'` or `'strict'` on session cookies, and never combine `Access-Control-Allow-Origin: *` with credentials."
  },
  {
    key: "secrets_or_env_leak",
    title: "Hardcoded Secrets, Credential Logging, or Client Env Leak",
    instructions:
      "Does the code hardcode API keys/passwords/tokens, log sensitive credentials/headers, or expose server-only secrets to client bundles (e.g., `NEXT_PUBLIC_` or returning full user/env objects)?",
    searchKeywords: ["secrets", "process.env", "NEXT_PUBLIC", "logging", "credentials"],
    fallbackGuidance:
      "Load secrets exclusively from server-side environment variables or secret managers, redact sensitive fields from logs and error responses, and never expose server secrets to client components."
  },
  {
    key: "cache_or_state_leak",
    title: "Cross-User Cache Poisoning or Shared State Data Leak",
    instructions:
      "Could user-specific or authenticated data be cached in a shared/static cache (`use cache`, `force-cache`, CDN `Cache-Control: public`, or module-scoped mutable variables) and leaked to other users?",
    searchKeywords: ["Cache", "data-leak", "static rendering", "use cache"],
    fallbackGuidance:
      "Never cache per-user or authenticated responses in shared/static caches without strict per-user cache keys, and set `Cache-Control: private, no-store` on sensitive endpoints."
  },
  {
    key: "dos_or_unbounded_resource",
    title: "Denial of Service (DoS), Unbounded Pagination, or Unsafe File Upload",
    instructions:
      "Does the code allow unbounded database queries (missing `limit` cap), unrestricted file uploads (missing size/count/MIME checks), expensive endpoints without rate-limiting, or external calls without timeouts?",
    searchKeywords: ["upload", "pagination", "timeout", "rate limit", "size"],
    fallbackGuidance:
      "Enforce hard upper bounds on pagination (`limit <= 100`), request body size, file upload size/type (with generated filenames), and outbound network timeouts."
  },
  {
    key: "shallow_module_or_arch_flaw",
    title: "Shallow Module / Leaky Interface / Poor Test Seam (Codebase Design)",
    instructions:
      "Does the code expose internal implementation details through a complex/leaky interface, tangle I/O with pure domain logic, or make unit testing impossible without brittle private mocking?",
    searchKeywords: ["deep module", "interface", "seam", "boundary"],
    fallbackGuidance:
      "Design deep modules: keep public interfaces small and obvious while hiding implementation complexity behind clean dependency-injected seams."
  }
];

export const ARCHITECTURE_VECTOR_KEY = "shallow_module_or_arch_flaw";

export const GSAP_ANIMATION_VECTOR: VectorMetadata = {
  key: "gsap_layout_thrashing_or_cleanup",
  title: "GSAP Animation Performance / Lifecycle Violation (60fps Directive)",
  instructions:
    "Does this animation code animate layout-triggering CSS properties (`top`, `left`, `width`, `height`, `margin`) instead of GPU transforms (`x`, `y`, `scale`, `rotation`, `opacity`), omit `useGSAP()` cleanup in React, or use `gsap.to()` inside mousemove loops instead of `gsap.quickTo()`?",
  searchKeywords: ["transform", "quickTo", "useGSAP", "will-change", "pointer-events"],
  fallbackGuidance:
    "Always animate GPU transform properties (`x`, `y`, `scale`, `rotation`, `opacity`) instead of `top`/`left`/`width`/`height`, use `useGSAP()` for React lifecycle cleanup, use `gsap.quickTo()` for high-frequency mouse tracking, and set `pointer-events: none` on overlays."
};

const STACK_TO_SKILL_FILE: Record<CodeStack, string> = {
  nextjs: "security-best-practices/references/javascript-typescript-nextjs-web-server-security.md",
  express: "security-best-practices/references/javascript-express-web-server-security.md",
  react: "security-best-practices/references/javascript-typescript-react-web-frontend-security.md",
  vue: "security-best-practices/references/javascript-typescript-vue-web-frontend-security.md",
  frontend: "security-best-practices/references/javascript-general-web-frontend-security.md",
  fastapi: "security-best-practices/references/python-fastapi-web-server-security.md",
  django: "security-best-practices/references/python-django-web-server-security.md",
  flask: "security-best-practices/references/python-flask-web-server-security.md",
  golang: "security-best-practices/references/golang-general-backend-security.md",
  gsap: "gsap-performance/SKILL.md",
  general: "security-best-practices/SKILL.md"
};

/**
 * Third-party remediation skills shipped inside this package (skills/vendor/), vendored
 * verbatim at pinned commits by scripts/vendor-skills.mjs. See THIRD_PARTY_NOTICES.md.
 * Resolved from this module's location (dist/src/core/), never from process.cwd().
 */
export const BUNDLED_SKILLS_DIR = fileURLToPath(new URL("../../../skills/vendor/", import.meta.url));

export function resolveSkillsDir(customDir?: string): string {
  const home = os.homedir();
  if (customDir && customDir.trim().length > 0) {
    return customDir.trim();
  }
  if (process.env.JEV_SKILLS_DIR && process.env.JEV_SKILLS_DIR.trim().length > 0) {
    return process.env.JEV_SKILLS_DIR.trim();
  }

  const candidates = [
    path.join(home, ".gemini", "config", "skills"),
    path.join(home, ".claude", "skills"),
    path.join(home, ".agents", "skills"),
    path.join(home, ".cursor", "skills"),
    path.resolve(process.cwd(), ".agents", "skills"),
    path.resolve(process.cwd(), "skills")
  ];

  // Prefer a directory that actually contains the security/animation skill rubrics
  for (const dir of candidates) {
    if (
      fs.existsSync(path.join(dir, "security-best-practices")) ||
      fs.existsSync(path.join(dir, "gsap-performance"))
    ) {
      return dir;
    }
  }
  for (const dir of candidates) {
    if (fs.existsSync(dir)) {
      return dir;
    }
  }
  return BUNDLED_SKILLS_DIR;
}

export function detectCodeStack(codeOrDiff: string, filePath = ""): CodeStack {
  const sample = `${filePath}\n${codeOrDiff}`;

  if (
    /\b(?:from|import)\s+["'](?:gsap|@gsap\/react)(?:\/[^"']*)?["']|\bgsap\.(?:to|from|fromTo|set|timeline|quickTo|registerPlugin|context|matchMedia)\s*\(|\buseGSAP\s*\(|\bScrollTrigger\.(?:create|refresh|batch|defaults)\s*\(/.test(
      sample
    )
  ) {
    return "gsap";
  }
  const hasExplicitExt = /\.[a-z0-9]+$/i.test(filePath);
  const canBePython = !hasExplicitExt || /\.pyw?$/i.test(filePath);
  const canBeGolang = !hasExplicitExt || /\.go$/i.test(filePath);

  if (
    /\bnext\/server\b|\bnext\/headers\b|\bnext\/navigation\b|\bNextRequest\b|\bNextResponse\b|next\.config/i.test(
      sample
    )
  ) {
    return "nextjs";
  }
  if (canBePython && /\bfastapi\b|\bAPIRouter\b|\bDepends\(/.test(sample)) {
    return "fastapi";
  }
  if (canBePython && /\bdjango\b|\bHttpResponse\b|\bmodels\.Model\b/i.test(sample)) {
    return "django";
  }
  if (canBePython && /\bfrom\s+flask\s+import\b|\bFlask\(__name__\)/i.test(sample)) {
    return "flask";
  }
  if (canBeGolang && (/\.go\b/.test(filePath) || /\bpackage\s+main\b|\bnet\/http\b|\bfmt\.Println\b/.test(sample))) {
    return "golang";
  }
  if (/\bexpress\s*\(|\bapp\.use\(|\breq,\s*res,\s*next\b/.test(sample)) {
    return "express";
  }
  if (/\.vue\b|\bv-html\b|\bdefineComponent\b/.test(sample)) {
    return "vue";
  }
  if (
    /\.(tsx|jsx)$/i.test(filePath) ||
    /\buseState\s*\(|\buseEffect\s*\(|\bdangerouslySetInnerHTML\b/.test(sample)
  ) {
    return "react";
  }
  if (/\.html\b|\bdocument\.querySelector\b|\bwindow\.location\b/.test(sample)) {
    return "frontend";
  }
  return "general";
}

/** Vectors that are design/performance advice, never a security BLOCK on their own. */
const NON_SECURITY_VECTOR_KEYS: ReadonlySet<string> = new Set([
  ARCHITECTURE_VECTOR_KEY,
  GSAP_ANIMATION_VECTOR.key
]);

const ANIMATION_STACKS: ReadonlySet<CodeStack> = new Set<CodeStack>(["gsap", "react", "frontend"]);

export function stackIncludesAnimation(stack: CodeStack): boolean {
  return ANIMATION_STACKS.has(stack);
}

export function buildSkillAuditQuestions(
  stack: CodeStack,
  includeAnimation = stackIncludesAnimation(stack)
): Record<string, JevQuestion> {
  const questions: Record<string, JevQuestion> = {};

  for (const vec of SECURITY_AUDIT_VECTORS) {
    questions[vec.key] = {
      type: "noul",
      instructions: `[Stack: ${stack}] ${vec.instructions}`
    };
  }

  if (includeAnimation) {
    questions[GSAP_ANIMATION_VECTOR.key] = {
      type: "noul",
      instructions: GSAP_ANIMATION_VECTOR.instructions
    };
  }

  questions.overall_security_score = {
    type: "score",
    instructions:
      "Rate the overall security, resilience, and architectural quality of this code from 1 (critical vulnerabilities present) to 5 (exemplary secure-by-default implementation).",
    criteria: {
      "1": "Critical exploitable vulnerability or severe anti-pattern",
      "2": "High-risk security gap or missing input/auth validation",
      "3": "Moderate risk or incomplete defensive controls",
      "4": "Solid implementation with only minor hardening suggestions",
      "5": "Exemplary secure-by-default, well-bounded, and high-performance code"
    }
  };

  questions.audit_verdict = {
    type: "choice",
    instructions: "What action should the coding agent take based on this skill audit?",
    criteria: {
      clean_pass: "Code adheres to security and engineering skills; proceed immediately",
      review_warnings: "Minor hardening or structural improvements recommended",
      block_and_fix: "Material security vulnerability or critical skill rule violation detected; must fix before completing"
    }
  };

  return questions;
}

function extractMatchingSectionFromMarkdown(
  markdown: string,
  keywords: string[],
  maxChars = 1100
): string | null {
  const lines = markdown.split(/\r?\n/);
  for (const kw of keywords) {
    const lowerKw = kw.toLowerCase();
    // Prefer matching markdown headings first
    let matchIdx = lines.findIndex(
      (line) => /^#{1,4}\s+/.test(line) && line.toLowerCase().includes(lowerKw)
    );
    if (matchIdx === -1) {
      matchIdx = lines.findIndex((line) => line.toLowerCase().includes(lowerKw));
    }
    if (matchIdx !== -1) {
      const start = Math.max(0, matchIdx);
      const snippet = lines.slice(start, start + 28).join("\n").trim();
      if (snippet.length > 0) {
        return snippet.length > maxChars ? `${snippet.slice(0, maxChars)}\n...` : snippet;
      }
    }
  }
  return null;
}

export function extractSkillRemediation(
  skillsDir: string,
  stack: CodeStack,
  violatedVectors: Array<{ vector: string; probability: number }>,
  bundledDir: string = BUNDLED_SKILLS_DIR
): SkillRemediationExcerpt[] {
  const allVectors = [...SECURITY_AUDIT_VECTORS, GSAP_ANIMATION_VECTOR];
  const excerpts: SkillRemediationExcerpt[] = [];

  for (const item of violatedVectors) {
    const meta = allVectors.find((v) => v.key === item.vector);
    if (!meta) continue;

    let relativeSkillPath =
      stack === "gsap"
        ? STACK_TO_SKILL_FILE.react
        : STACK_TO_SKILL_FILE[stack] ?? STACK_TO_SKILL_FILE.general;
    if (item.vector === GSAP_ANIMATION_VECTOR.key) {
      relativeSkillPath = "gsap-performance/SKILL.md";
    } else if (item.vector === ARCHITECTURE_VECTOR_KEY) {
      relativeSkillPath = "codebase-design/SKILL.md";
    }

    // The user's own installed skills win; the copy bundled in this package fills any gap.
    const isBundled = (dir: string) => path.resolve(dir) === path.resolve(bundledDir);
    const lookups: Array<[string, "local" | "bundled"]> = [[skillsDir, isBundled(skillsDir) ? "bundled" : "local"]];
    if (!isBundled(skillsDir)) lookups.push([bundledDir, "bundled"]);

    let extractedText: string | null = null;
    let skillSource: SkillRemediationExcerpt["skillSource"] = "builtin";
    for (const [dir, source] of lookups) {
      extractedText = readSkillSection(path.join(dir, relativeSkillPath), meta.searchKeywords);
      if (extractedText) {
        skillSource = source;
        break;
      }
    }

    const sourceLabel =
      skillSource === "bundled" ? `${path.basename(relativeSkillPath)}, bundled with jev-codeguard` : path.basename(relativeSkillPath);
    excerpts.push({
      vector: item.vector,
      probability: item.probability,
      skillFile: relativeSkillPath,
      skillSource,
      title: meta.title,
      excerpt: extractedText
        ? `${meta.fallbackGuidance}\n\n--- [Extracted from ${sourceLabel}] ---\n${extractedText}`
        : meta.fallbackGuidance
    });
  }

  return excerpts;
}

function readSkillSection(fullPath: string, keywords: string[]): string | null {
  try {
    if (!fs.existsSync(fullPath)) return null;
    return extractMatchingSectionFromMarkdown(fs.readFileSync(fullPath, "utf8"), keywords);
  } catch {
    return null;
  }
}

export interface AuditCodeInput {
  code: string;
  filePath?: string;
  stack?: CodeStack;
  skillsDir?: string;
  violationThreshold?: number;
  projectContext?: unknown;
  fileHeaderContext?: Record<string, string>;
}

type ScoredVector = { vector: string; probability: number };

function formatVectors(vectors: ScoredVector[]): string {
  return vectors.map((v) => `${v.vector} (${v.probability.toFixed(2)})`).join(", ");
}

/**
 * Builds the audit explanation from the verdict that was actually reached, so a BLOCK
 * can never be described as "all checks passed" and GSAP is only mentioned when the
 * animation vector was really evaluated.
 */
export function buildAuditSummary(input: {
  verdict: GateVerdict;
  securityScore: number;
  threshold: number;
  includeAnimation: boolean;
  modelChoice: string;
  securityVectors: ScoredVector[];
  advisoryVectors: ScoredVector[];
  lowScoreReview: boolean;
}): string {
  const score = `${input.securityScore.toFixed(2)}/5`;
  const modelVote = input.modelChoice === "block_and_fix" ? ", model voted block_and_fix" : "";
  if (input.verdict === "BLOCK") {
    return `BLOCK: security vector(s) ${formatVectors(input.securityVectors)} with overall score ${score}${modelVote}.`;
  }
  if (input.verdict === "ASK_USER" && input.lowScoreReview) {
    const findings =
      input.securityVectors.length > 0
        ? `only low-confidence security findings (${formatVectors(input.securityVectors)})`
        : `no security vector crossed ${input.threshold}`;
    return `ASK_USER: ${findings}, but the overall score is ${score}${modelVote}; review manually before treating this code as clean.`;
  }
  if (input.verdict === "ASK_USER") {
    return `ASK_USER: review security vector(s) ${formatVectors(input.securityVectors)}; overall score ${score}.`;
  }
  const findings = [...input.securityVectors, ...input.advisoryVectors];
  if (findings.length > 0) {
    return `ALLOW with non-blocking findings: ${formatVectors(findings)}; overall score ${score}.`;
  }
  const securityCount = SECURITY_AUDIT_VECTORS.filter((v) => !NON_SECURITY_VECTOR_KEYS.has(v.key)).length;
  const families = [`${securityCount} security`, "1 architecture"];
  if (input.includeAnimation) families.push("1 GSAP animation");
  return `ALLOW: every checked vector (${families.join(" + ")}) stayed below ${input.threshold}; overall score ${score}.`;
}

export async function auditCodeWithSkills(
  client: JevClient,
  input: AuditCodeInput
): Promise<SkillAuditResult> {
  const policy = JEV_POLICY.audit;
  const stack = input.stack ?? detectCodeStack(input.code, input.filePath);
  const skillsDir = resolveSkillsDir(input.skillsDir);
  const threshold = input.violationThreshold ?? policy.violationThreshold;
  const includeAnimation = stackIncludesAnimation(stack);

  const questions = buildSkillAuditQuestions(stack, includeAnimation);
  const { response, latencyMs, cached } = await client.evaluate(
    {
      stack,
      file_path: input.filePath ?? "unknown",
      file_headers_and_auth_context:
        input.fileHeaderContext && Object.keys(input.fileHeaderContext).length > 0
          ? input.fileHeaderContext
          : undefined,
      project_dna: input.projectContext,
      code_or_diff: input.code.slice(0, 32000)
    },
    questions,
    { operation: "jev_audit_code" }
  );

  const allVectors = [...SECURITY_AUDIT_VECTORS, GSAP_ANIMATION_VECTOR];
  const violatedVectors: Array<{ vector: string; probability: number; description: string }> = [];
  const cleanVectors: string[] = [];

  for (const vec of allVectors) {
    const ans = response.answers[vec.key];
    if (!ans || ans.type !== "noul") continue;
    if (ans.noul >= threshold) {
      violatedVectors.push({
        vector: vec.key,
        probability: ans.noul,
        description: vec.title
      });
    } else {
      cleanVectors.push(vec.key);
    }
  }

  violatedVectors.sort((a, b) => b.probability - a.probability);

  const scoreAns = response.answers.overall_security_score;
  let securityScore = 3.0;
  if (scoreAns && scoreAns.type === "score") {
    if (scoreAns.probabilities && "0" in scoreAns.probabilities && !("5" in scoreAns.probabilities)) {
      let weighted = 0;
      for (const [k, p] of Object.entries(scoreAns.probabilities)) {
        const idx = Number(k);
        if (Number.isFinite(idx) && typeof p === "number") {
          weighted += (idx + 1) * p;
        }
      }
      securityScore = Number(Math.max(1, Math.min(5, weighted)).toFixed(2));
    } else {
      securityScore = scoreAns.score;
    }
  }

  const choiceAns = response.answers.audit_verdict;
  const modelChoice = choiceAns && choiceAns.type === "choice" ? choiceAns.selected : "clean_pass";

  const isTestFile = Boolean(
    input.filePath &&
      (/(?:^|[\\/])(tests?|__tests__|spec)(?:[\\/]|$)/i.test(input.filePath) ||
        /\.(test|spec)\.[a-z0-9]+$/i.test(input.filePath))
  );
  // Architecture and GSAP findings are advice; only security vectors can block. (The
  // previous filter used a misspelled GSAP key, so GSAP findings counted as security.)
  const securityVectorsOnly = violatedVectors.filter((v) => !NON_SECURITY_VECTOR_KEYS.has(v.vector));
  const advisoryVectors = violatedVectors.filter((v) => NON_SECURITY_VECTOR_KEYS.has(v.vector));

  let verdict: GateVerdict = "ALLOW";
  let lowScoreReview = false;
  if (
    securityVectorsOnly.length > 0 &&
    (securityScore < policy.blockScoreBelow ||
      (modelChoice === "block_and_fix" && securityScore < policy.blockModelVoteScoreBelow) ||
      (!isTestFile &&
        securityScore < policy.blockStrongVectorScoreBelow &&
        securityVectorsOnly.some((v) => v.probability >= policy.blockStrongVectorMin)) ||
      securityVectorsOnly.some((v) => v.probability >= policy.blockCriticalVectorMin))
  ) {
    verdict = "BLOCK";
  } else if (
    !isTestFile &&
    securityScore < policy.askScoreBelow &&
    securityVectorsOnly.some((v) => v.probability >= policy.askVectorMin)
  ) {
    verdict = "ASK_USER";
  } else if (
    !isTestFile &&
    securityVectorsOnly.every((v) => v.probability < policy.askVectorMin) &&
    (securityScore < policy.lowScoreReviewBelow || modelChoice === "block_and_fix")
  ) {
    // A low overall score without an attributable vector is a review signal, not a pass.
    verdict = "ASK_USER";
    lowScoreReview = true;
  }

  const skillExcerpts =
    violatedVectors.length > 0
      ? extractSkillRemediation(skillsDir, stack, violatedVectors)
      : [];

  const summary = buildAuditSummary({
    verdict,
    securityScore,
    threshold,
    includeAnimation,
    modelChoice,
    securityVectors: securityVectorsOnly,
    advisoryVectors,
    lowScoreReview
  });

  return {
    stack,
    verdict,
    summary,
    securityScore,
    violatedVectors,
    cleanVectors,
    skillExcerpts,
    rawAnswers: response.answers,
    latencyMs,
    cached,
    usage: response.usage
  };
}
