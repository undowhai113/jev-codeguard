import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import {
  buildProjectContextEnvelope,
  buildSpecRequirementMatrix,
  extractCompanionTestsContext,
  extractCrossFileContracts,
  extractDomainAndRuntimeFingerprint,
  extractFileHeaderContext,
  extractPostEditHunkScopes,
  extractReferencedDocsAndFiles,
  extractReverseDependents,
  extractStructuralDiffMap,
  isGenericHostDirectory,
  isSensitiveFilePath,
  isWithinWorkspaceBoundary,
  recordProjectFeedbackRule,
  removeProjectFeedbackRule,
  resolveTargetWorkspace,
  runFastSyntaxProbe,
  syncProjectBrainProfile
} from "../src/core/context-enricher.js";
import {
  extractHybridAstSkeletons,
  queryCodeGraphIntelligence,
  runHybridStaticAnalysis
} from "../src/core/hybrid-ast-engine.js";

test("extractStructuralDiffMap parses added symbols, CSS classes, tests, and hunk headers across multiple files", () => {
  const sampleDiff = [
    "diff --git a/apps/web/src/features/match/MatchScreen.tsx b/apps/web/src/features/match/MatchScreen.tsx",
    "--- a/apps/web/src/features/match/MatchScreen.tsx",
    "+++ b/apps/web/src/features/match/MatchScreen.tsx",
    "@@ -10,4 +10,12 @@ export function MatchHeader() {",
    "+export function RoleInspectorModal() {",
    "+  const activeRule = true;",
    "+}",
    "diff --git a/apps/web/src/features/match/match.css b/apps/web/src/features/match/match.css",
    "--- a/apps/web/src/features/match/match.css",
    "+++ b/apps/web/src/features/match/match.css",
    "@@ -50,2 +50,8 @@",
    "+.kp-arena {",
    "+  grid-template-rows: minmax(0, 1fr);",
    "+}"
  ].join("\n");

  const map = extractStructuralDiffMap(sampleDiff);
  assert.equal(map.length, 2);
  assert.equal(map[0].file, "apps/web/src/features/match/MatchScreen.tsx");
  assert.equal(map[0].addedLines, 3);
  assert.ok(map[0].touchedSymbols.includes("RoleInspectorModal"));
  assert.equal(map[1].file, "apps/web/src/features/match/match.css");
  assert.ok(map[1].touchedSymbols.includes(".kp-arena"));
});

test("buildProjectContextEnvelope and extractFileHeaderContext harvest workspace DNA, repo topology, and file headers", () => {
  const dna = buildProjectContextEnvelope(process.cwd());
  assert.ok(dna.workspaceName.length > 0);
  assert.ok(dna.stackSummary.includes("jev-codeguard"));
  assert.ok(dna.repoTopology.includes("src/"));

  const headers = extractFileHeaderContext(process.cwd(), "src/core/types.ts");
  assert.ok(headers["src/core/types.ts"]?.includes("JevQuestionType"));
});

test("resolveTargetWorkspace ignores Antigravity host folder and resolves real workspace from path hints", () => {
  assert.equal(
    isGenericHostDirectory("C:\\Users\\Developer\\AppData\\Local\\Programs\\Antigravity"),
    true
  );
  const resolved = resolveTargetWorkspace(
    "C:\\Users\\Developer\\AppData\\Local\\Programs\\Antigravity",
    [`Update ${process.cwd()}\\src\\core\\policy-engine.ts`]
  );
  assert.equal(resolved.toLowerCase(), process.cwd().toLowerCase());
});

test("isSensitiveFilePath and isWithinWorkspaceBoundary prevent secret exfiltration and path traversal", () => {
  assert.equal(isSensitiveFilePath(".env"), true);
  assert.equal(isSensitiveFilePath(".env.production"), true);
  assert.equal(isSensitiveFilePath("certs/server.pem"), true);
  assert.equal(isSensitiveFilePath("~/.ssh/id_rsa"), true);
  assert.equal(isSensitiveFilePath(".env.example"), false);
  assert.equal(isSensitiveFilePath("src/core/types.ts"), false);

  assert.equal(
    isWithinWorkspaceBoundary(process.cwd(), path.join(process.cwd(), "src", "core", "types.ts")),
    true
  );
  assert.equal(
    isWithinWorkspaceBoundary(process.cwd(), path.resolve(process.cwd(), "..", "..", "outside.txt")),
    false
  );
});

test("extractReferencedDocsAndFiles automatically reads files cited inside spec or prompt", () => {
  const docs = extractReferencedDocsAndFiles(process.cwd(), [
    "Implement changes according to README.md and check src/core/types.ts"
  ]);
  assert.ok(docs["README.md"] || docs["src/core/types.ts"]);
  assert.ok(docs["src/core/types.ts"]?.includes("GateVerdict"));
});

test("extractPostEditHunkScopes and extractCrossFileContracts pull surrounding function scope and imported types", () => {
  const sampleDiff = [
    "diff --git a/src/core/policy-engine.ts b/src/core/policy-engine.ts",
    "--- a/src/core/policy-engine.ts",
    "+++ b/src/core/policy-engine.ts",
    "@@ -35,4 +35,6 @@ export function evaluateCommandGate(",
    "+  const safeCheck = true;"
  ].join("\n");

  const scopes = extractPostEditHunkScopes(process.cwd(), sampleDiff);
  assert.ok(scopes["src/core/policy-engine.ts"]?.includes("L35:"));

  const contracts = extractCrossFileContracts(process.cwd(), ["src/core/policy-engine.ts"]);
  assert.ok(
    Object.keys(contracts).some((k) => k.endsWith("src/core/types.ts")),
    "Should resolve ./types.js import to src/core/types.ts and extract exported interfaces"
  );
});

test("buildSpecRequirementMatrix maps numbered requirements to changed files and touched symbols", () => {
  const spec =
    "(1) Add RoleInspectorModal to MatchScreen.tsx (2) Update .kp-arena grid rules in match.css";
  const sampleDiff = [
    "diff --git a/apps/web/src/features/match/MatchScreen.tsx b/apps/web/src/features/match/MatchScreen.tsx",
    "+++ b/apps/web/src/features/match/MatchScreen.tsx",
    "@@ -10,2 +10,6 @@",
    "+export function RoleInspectorModal() {}",
    "diff --git a/apps/web/src/features/match/match.css b/apps/web/src/features/match/match.css",
    "+++ b/apps/web/src/features/match/match.css",
    "@@ -20,2 +20,5 @@",
    "+.kp-arena { display: grid; }"
  ].join("\n");

  const structuralMap = extractStructuralDiffMap(sampleDiff);
  const matrix = buildSpecRequirementMatrix(spec, structuralMap, sampleDiff);
  assert.equal(matrix.length, 2);
  assert.equal(matrix[0].id, "REQ_1");
  assert.ok(matrix[0].matchedFiles.includes("apps/web/src/features/match/MatchScreen.tsx"));
  assert.equal(matrix[1].id, "REQ_2");
  assert.ok(matrix[1].matchedFiles.includes("apps/web/src/features/match/match.css"));
});

test("extractReverseDependents and extractCompanionTestsContext discover callers and existing test suites", () => {
  const rev = extractReverseDependents(
    process.cwd(),
    ["src/core/policy-engine.ts"],
    [
      {
        file: "src/core/policy-engine.ts",
        addedLines: 4,
        removedLines: 1,
        hunkHeaders: ["evaluateCommandGate"],
        touchedSymbols: ["evaluateCommandGate"]
      }
    ]
  );
  assert.ok(
    rev.unmodifiedDependents.includes("src/mcp/server.ts"),
    "Should identify src/mcp/server.ts as an unmodified caller of policy-engine.ts"
  );
  assert.ok(
    rev.referencedTouchedSymbols.evaluateCommandGate?.includes("src/mcp/server.ts")
  );

  const companionTests = extractCompanionTestsContext(process.cwd(), [
    "src/core/policy-engine.ts"
  ]);
  assert.ok(
    companionTests["tests/policy-presets.test.ts"]?.length > 0,
    "Should discover tests/policy-presets.test.ts (which imports policy-engine) and extract its test titles"
  );

  const fingerprint = extractDomainAndRuntimeFingerprint(process.cwd());
  assert.equal(typeof fingerprint, "string");

  const dna = buildProjectContextEnvelope(process.cwd());
  const brainPath = syncProjectBrainProfile(dna);
  assert.ok(brainPath && brainPath.endsWith(".json"));

  const savedRule = recordProjectFeedbackRule({
    workspaceName: dna.workspaceName,
    workspacePath: process.cwd(),
    tool: "jev_verify_diff",
    feedbackType: "FALSE_POSITIVE_OVERRIDE",
    rule: "Allow handoff markdown checkpoints without blocking"
  });
  assert.ok(savedRule.id.startsWith("rule_"));

  const refreshedDna = buildProjectContextEnvelope(process.cwd());
  assert.ok(
    refreshedDna.learnedHumanOverrides?.some((r) => r.id === savedRule.id),
    "Learned human feedback rule should be automatically loaded into ProjectDnaEnvelope"
  );

  const removed = removeProjectFeedbackRule(dna.workspaceName, savedRule.id);
  assert.equal(removed, true);

  const syntaxReport = runFastSyntaxProbe(process.cwd(), ["package.json"]);
  assert.equal(syntaxReport.status, "PASS");
  assert.ok(syntaxReport.checkedFiles.includes("package.json"));
});

test("Hybrid AST & Linter Engine extracts ts-morph AST skeletons, runs oxlint/ruff, and queries CodeGraph", () => {
  // The fixture is the real policy-engine.ts; derive the edited line from it instead of
  // hard-coding a line number that breaks whenever the file is reorganized.
  const policyLines = fs
    .readFileSync(path.join(process.cwd(), "src/core/policy-engine.ts"), "utf8")
    .split(/\r?\n/);
  const gateLine = policyLines.findIndex((l) => l.startsWith("export function evaluateCommandGate(")) + 1;
  assert.ok(gateLine > 0, "fixture must define evaluateCommandGate");
  const editedLine = gateLine + 8; // inside the function body
  const sampleDiff = [
    "diff --git a/src/core/policy-engine.ts b/src/core/policy-engine.ts",
    "--- a/src/core/policy-engine.ts",
    "+++ b/src/core/policy-engine.ts",
    `@@ -${editedLine},4 +${editedLine},6 @@`,
    "+  const checked = true;"
  ].join("\n");

  const skeletons = extractHybridAstSkeletons(
    process.cwd(),
    ["src/core/policy-engine.ts", "src/core/types.ts"],
    sampleDiff
  );
  assert.equal(skeletons.length, 2);
  assert.equal(skeletons[0].language, "typescript");
  assert.ok(
    skeletons[0].exportedSignatures.some((s) => s.includes("function evaluateCommandGate")),
    "ts-morph should extract full exported function signature for evaluateCommandGate"
  );
  assert.ok(
    skeletons[0].enclosingModifiedNodes.some((n) => n.includes("evaluateCommandGate")),
    "ts-morph should identify evaluateCommandGate as the enclosing AST node of the edited line"
  );
  assert.ok(
    skeletons[1].exportedSignatures.some((s) => s.includes("interface PolicyDecision")),
    "ts-morph should extract exported interface PolicyDecision with its properties"
  );

  const staticReport = runHybridStaticAnalysis(process.cwd(), [
    "src/core/policy-engine.ts",
    "package.json"
  ]);
  assert.ok(staticReport.enginesUsed.includes("ts-morph-ast"));
  assert.ok(staticReport.checkedFiles.includes("src/core/policy-engine.ts"));

  const cgReport = queryCodeGraphIntelligence(process.cwd(), "verify diff policy gate", [
    "src/core/policy-engine.ts"
  ]);
  assert.equal(typeof cgReport.indexed, "boolean");
});
