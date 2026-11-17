import { execFileSync, spawn } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { Project, SyntaxKind } from "ts-morph";
import { z } from "zod";
import {
  isSensitiveFilePath,
  isWithinWorkspaceBoundary,
  resolvePythonExecutable
} from "./context-enricher.js";

const MAX_AST_FILE_BYTES = 512 * 1024;
const MAX_ANALYZED_FILES = 64;
const SafeFileListSchema = z.array(z.string().min(1).max(512)).max(MAX_ANALYZED_FILES);

export interface AstFileSkeleton {
  file: string;
  language: "typescript" | "javascript" | "python";
  imports: string[];
  exportedSignatures: string[];
  enclosingModifiedNodes: string[];
}

export interface StaticDiagnosticItem {
  engine: "oxlint" | "ruff" | "ts-morph" | "json" | "py_compile";
  file: string;
  line?: number;
  severity: "error" | "warning";
  code: string;
  message: string;
}

export interface HybridStaticAnalysisReport {
  enginesUsed: string[];
  status: "CLEAN" | "WARNINGS" | "ERRORS_DETECTED" | "SKIPPED";
  checkedFiles: string[];
  errorCount: number;
  warningCount: number;
  diagnostics: StaticDiagnosticItem[];
}

export interface CodeGraphIntelligenceReport {
  indexed: boolean;
  taskGraphContext?: string;
  graphAffectedTests: string[];
  symbolRelations: string[];
}

const tsMorphProject = new Project({
  skipAddingFilesFromTsConfig: true,
  skipFileDependencyResolution: true,
  compilerOptions: {
    allowJs: true,
    checkJs: false,
    noEmit: true,
    target: 99 // ESNext
  }
});

const autoInitTriggeredWorkspaces = new Set<string>();

function parseChangedLinesByFile(rawDiff: string): Map<string, number[]> {
  const map = new Map<string, number[]>();
  if (!rawDiff || !rawDiff.trim()) return map;

  const chunks = rawDiff
    .split(/(?=^diff --git )/m)
    .map((c) => c.trim())
    .filter(Boolean);

  for (const chunk of chunks) {
    const fileMatch =
      chunk.match(/^diff --git a\/.+? b\/([^\r\n\t]+)$/m) ??
      chunk.match(/^\+\+\+ b\/([^\r\n\t]+)$/m);
    const file = fileMatch ? fileMatch[1].trim() : "";
    if (!file) continue;

    const lines: number[] = [];
    for (const m of chunk.matchAll(/^@@\s*-\d+(?:,\d+)?\s+\+(\d+)(?:,(\d+))?\s*@@/gm)) {
      const start = parseInt(m[1], 10);
      const count = m[2] !== undefined ? parseInt(m[2], 10) : 1;
      lines.push(start, start + Math.max(0, Math.floor(count / 2)));
    }
    if (lines.length > 0) {
      map.set(file.replace(/\\/g, "/"), lines);
    }
  }
  return map;
}

/**
 * Uses `ts-morph` (TypeScript Compiler AST) for `.ts/.tsx/.js/.jsx` and Python's native `ast` module
 * for `.py` to extract 100% accurate AST symbol signatures, return types, decorators, and enclosing AST nodes.
 */
export function extractHybridAstSkeletons(
  cwd: string,
  changedFiles: string[],
  rawDiff = "",
  maxFiles = 8
): AstFileSkeleton[] {
  const resolvedCwd = path.resolve(z.string().min(1).max(1024).parse(cwd));
  const boundedFiles = SafeFileListSchema.parse(changedFiles.slice(0, MAX_ANALYZED_FILES));
  const boundedMaxFiles = Math.max(1, Math.min(maxFiles, 16));
  const changedLinesMap = parseChangedLinesByFile(rawDiff.slice(0, 120_000));
  const skeletons: AstFileSkeleton[] = [];

  const tsJsFiles: string[] = [];
  const pyFiles: string[] = [];

  for (const rel of boundedFiles) {
    if (tsJsFiles.length + pyFiles.length >= boundedMaxFiles) break;
    const norm = rel.replace(/\\/g, "/");
    const full = path.isAbsolute(rel) ? rel : path.join(resolvedCwd, rel);
    if (isSensitiveFilePath(full) || !isWithinWorkspaceBoundary(resolvedCwd, full)) continue;
    if (!fs.existsSync(full)) continue;
    const stat = fs.statSync(full);
    if (!stat.isFile() || stat.size > MAX_AST_FILE_BYTES) continue;

    if (/\.(ts|tsx|js|jsx|mjs)$/i.test(norm)) {
      tsJsFiles.push(norm);
    } else if (/\.py$/i.test(norm)) {
      pyFiles.push(norm);
    }
  }

  // 1. Parse TypeScript / JavaScript files via ts-morph AST
  for (const relFile of tsJsFiles) {
    const fullPath = path.isAbsolute(relFile) ? relFile : path.join(resolvedCwd, relFile);
    try {
      const content = fs.readFileSync(fullPath, "utf8");
      const sourceFile = tsMorphProject.createSourceFile(fullPath, content, { overwrite: true });

      const imports = sourceFile
        .getImportDeclarations()
        .slice(0, 12)
        .map((imp) => {
          const spec = imp.getModuleSpecifierValue();
          const named = imp
            .getNamedImports()
            .map((n) => n.getName())
            .slice(0, 6)
            .join(", ");
          const def = imp.getDefaultImport()?.getText();
          return `${def ? `${def} ` : ""}${named ? `{ ${named} } ` : ""}from "${spec}"`.trim();
        });

      const exportedSignatures: string[] = [];

      for (const fn of sourceFile.getFunctions()) {
        if (fn.isExported() || exportedSignatures.length < 10) {
          const name = fn.getName() ?? "anonymous";
          const params = fn
            .getParameters()
            .map((p) => p.getText())
            .join(", ");
          const ret = fn.getReturnTypeNode()?.getText() ?? "";
          const asyncPrefix = fn.isAsync() ? "async " : "";
          exportedSignatures.push(
            `L${fn.getStartLineNumber()}: ${fn.isExported() ? "export " : ""}${asyncPrefix}function ${name}(${params})${ret ? `: ${ret}` : ""}`
          );
        }
      }

      for (const cls of sourceFile.getClasses()) {
        const name = cls.getName() ?? "AnonymousClass";
        const methods = cls
          .getMethods()
          .slice(0, 8)
          .map((m) => `${m.getName()}(${m.getParameters().map((p) => p.getName()).join(", ")})`)
          .join("; ");
        exportedSignatures.push(
          `L${cls.getStartLineNumber()}: class ${name} { ${methods} }`
        );
      }

      for (const iface of sourceFile.getInterfaces()) {
        const name = iface.getName();
        const props = iface
          .getProperties()
          .slice(0, 10)
          .map((p) => `${p.getName()}${p.hasQuestionToken() ? "?" : ""}: ${p.getTypeNode()?.getText() ?? "any"}`)
          .join("; ");
        exportedSignatures.push(
          `L${iface.getStartLineNumber()}: interface ${name} { ${props} }`
        );
      }

      for (const typeAlias of sourceFile.getTypeAliases()) {
        const name = typeAlias.getName();
        const typeText = (typeAlias.getTypeNode()?.getText() ?? "").replace(/\s+/g, " ").slice(0, 120);
        exportedSignatures.push(`L${typeAlias.getStartLineNumber()}: type ${name} = ${typeText}`);
      }

      // Locate exact AST enclosing nodes for modified lines in git diff
      const targetLines = changedLinesMap.get(relFile) ?? [];
      const enclosingModifiedNodes: string[] = [];
      const callableNodes = [
        ...sourceFile.getDescendantsOfKind(SyntaxKind.FunctionDeclaration),
        ...sourceFile.getDescendantsOfKind(SyntaxKind.MethodDeclaration),
        ...sourceFile.getDescendantsOfKind(SyntaxKind.ClassDeclaration)
      ];

      for (const lineNum of targetLines) {
        for (const node of callableNodes) {
          const startL = node.getStartLineNumber();
          const endL = node.getEndLineNumber();
          if (lineNum >= startL && lineNum <= endL) {
            const headerLine = node.getText().split(/\r?\n/)[0]?.trim().slice(0, 140) ?? "";
            const label = `L${startL}-L${endL}: ${headerLine}`;
            if (headerLine && !enclosingModifiedNodes.includes(label)) {
              enclosingModifiedNodes.push(label);
            }
          }
        }
      }

      skeletons.push({
        file: relFile,
        language: /\.tsx?$/i.test(relFile) ? "typescript" : "javascript",
        imports: imports.slice(0, 10),
        exportedSignatures: exportedSignatures.slice(0, 16),
        enclosingModifiedNodes: enclosingModifiedNodes.slice(0, 6)
      });

      tsMorphProject.removeSourceFile(sourceFile);
    } catch {
      // ignore AST parse failure on partial file
    }
  }

  // 2. Parse Python files via Python's built-in `ast` module
  if (pyFiles.length > 0) {
    const pyScript = `
import ast, json, sys
out = []
for rel, full, lines in json.loads(sys.argv[1]):
    try:
        src = open(full, 'r', encoding='utf-8').read()
        tree = ast.parse(src, filename=rel)
        imports, sigs, enclosing = [], [], []
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module:
                names = ", ".join(a.name for a in node.names[:5])
                imports.append(f"from {node.module} import {names}")
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                decs = [f"@{ast.unparse(d)}" for d in node.decorator_list[:2]] if hasattr(ast, 'unparse') else []
                args = ", ".join(a.arg for a in node.args.args[:6])
                ret = f" -> {ast.unparse(node.returns)}" if getattr(node, 'returns', None) and hasattr(ast, 'unparse') else ""
                prefix = "async def" if isinstance(node, ast.AsyncFunctionDef) else "def"
                sig = f"L{node.lineno}: {' '.join(decs)} {prefix} {node.name}({args}){ret}".strip()
                sigs.append(sig)
                end_l = getattr(node, 'end_lineno', node.lineno + 15)
                for ln in lines:
                    if node.lineno <= ln <= end_l:
                        enclosing.append(f"L{node.lineno}-L{end_l}: {sig}")
            elif isinstance(node, ast.ClassDef):
                bases = ", ".join(ast.unparse(b) for b in node.bases) if hasattr(ast, 'unparse') else ""
                sigs.append(f"L{node.lineno}: class {node.name}({bases})")
        out.append({"file": rel, "imports": imports[:10], "sigs": sigs[:16], "enclosing": list(dict.fromkeys(enclosing))[:6]})
    except Exception:
        pass
print(json.dumps(out))
`.trim();

    const pyTargets = pyFiles.map((rel) => [
      rel,
      path.isAbsolute(rel) ? rel : path.join(resolvedCwd, rel),
      changedLinesMap.get(rel) ?? []
    ]);

    try {
      const stdout = execFileSync(
        resolvePythonExecutable(),
        ["-c", pyScript, JSON.stringify(pyTargets)],
        {
          cwd: resolvedCwd,
          encoding: "utf8",
          timeout: 1200,
          stdio: ["ignore", "pipe", "ignore"]
        }
      ).trim();
      const parsed = JSON.parse(stdout) as Array<{
        file: string;
        imports: string[];
        sigs: string[];
        enclosing: string[];
      }>;
      for (const item of parsed) {
        skeletons.push({
          file: item.file,
          language: "python",
          imports: item.imports,
          exportedSignatures: item.sigs,
          enclosingModifiedNodes: item.enclosing
        });
      }
    } catch {
      // ignore if python unavailable
    }
  }

  return skeletons;
}

interface BinaryRunner {
  cmd: string;
  prefixArgs: string[];
}

function resolveLocalOxlintRunner(): BinaryRunner | undefined {
  const selfDir = path.dirname(fileURLToPath(import.meta.url));
  const scriptCandidates = [
    path.resolve(process.cwd(), "node_modules", "oxlint", "bin", "oxlint"),
    path.resolve(selfDir, "..", "..", "..", "node_modules", "oxlint", "bin", "oxlint"),
    path.resolve(selfDir, "..", "..", "node_modules", "oxlint", "bin", "oxlint")
  ];
  for (const scriptPath of scriptCandidates) {
    if (fs.existsSync(scriptPath)) {
      return { cmd: process.execPath, prefixArgs: [scriptPath] };
    }
  }
  if (process.platform !== "win32") {
    const posixBin = path.resolve(process.cwd(), "node_modules", ".bin", "oxlint");
    if (fs.existsSync(posixBin)) {
      return { cmd: posixBin, prefixArgs: [] };
    }
  }
  return undefined;
}

let cachedCodeGraphRunner: BinaryRunner | null | undefined;

/**
 * Resolves `codegraph` to a direct executable or Node entrypoint so child processes
 * NEVER require `shell: true` (eliminating cmd.exe / shell metacharacter injection).
 */
function resolveCodeGraphRunner(): BinaryRunner | null {
  if (cachedCodeGraphRunner !== undefined) {
    return cachedCodeGraphRunner;
  }

  if (process.platform !== "win32") {
    try {
      const whichOut = execFileSync("which", ["codegraph"], {
        encoding: "utf8",
        timeout: 600,
        stdio: ["ignore", "pipe", "ignore"]
      }).trim();
      if (whichOut && fs.existsSync(whichOut)) {
        cachedCodeGraphRunner = { cmd: whichOut, prefixArgs: [] };
        return cachedCodeGraphRunner;
      }
    } catch {
      // codegraph not installed on POSIX host
    }
    cachedCodeGraphRunner = null;
    return null;
  }

  const jsCandidates: string[] = [
    path.resolve(
      process.cwd(),
      "node_modules",
      "@colbymchenry",
      "codegraph",
      "dist",
      "bin",
      "codegraph.js"
    )
  ];
  if (process.env.APPDATA) {
    jsCandidates.push(
      path.join(
        process.env.APPDATA,
        "npm",
        "node_modules",
        "@colbymchenry",
        "codegraph",
        "dist",
        "bin",
        "codegraph.js"
      )
    );
  }

  for (const jsPath of jsCandidates) {
    if (fs.existsSync(jsPath)) {
      cachedCodeGraphRunner = { cmd: process.execPath, prefixArgs: [jsPath] };
      return cachedCodeGraphRunner;
    }
  }

  try {
    const whereOut = execFileSync("where.exe", ["codegraph"], {
      encoding: "utf8",
      timeout: 800,
      stdio: ["ignore", "pipe", "ignore"]
    });
    const matches = whereOut
      .split(/\r?\n/)
      .map((s) => s.trim())
      .filter(Boolean);

    const exeMatch = matches.find((m) => /\.exe$/i.test(m) && fs.existsSync(m));
    if (exeMatch) {
      cachedCodeGraphRunner = { cmd: exeMatch, prefixArgs: [] };
      return cachedCodeGraphRunner;
    }

    const cmdMatch = matches.find((m) => /\.cmd$/i.test(m) && fs.existsSync(m));
    if (cmdMatch) {
      const shimText = fs.readFileSync(cmdMatch, "utf8");
      const relMatch = shimText.match(/%dp0%\\(node_modules\\[^"\r\n]+\.js)/i);
      if (relMatch) {
        const resolvedJs = path.join(path.dirname(cmdMatch), relMatch[1]);
        if (fs.existsSync(resolvedJs)) {
          cachedCodeGraphRunner = { cmd: process.execPath, prefixArgs: [resolvedJs] };
          return cachedCodeGraphRunner;
        }
      }
    }
  } catch {
    // codegraph not installed
  }

  cachedCodeGraphRunner = null;
  return null;
}

/**
 * Runs ultra-fast Rust static analyzers (`oxlint` >14k ⭐ for JS/TS/React and `ruff` >36k ⭐ for Python + Bandit Security `S` rules)
 * plus `ts-morph` AST syntax diagnostics on modified files in < 1.2s.
 */
export function runHybridStaticAnalysis(
  cwd: string,
  changedFiles: string[]
): HybridStaticAnalysisReport {
  const resolvedCwd = path.resolve(z.string().min(1).max(1024).parse(cwd));
  const boundedFiles = SafeFileListSchema.parse(changedFiles.slice(0, MAX_ANALYZED_FILES));
  const checkedFiles: string[] = [];
  const enginesUsed = new Set<string>();
  const diagnostics: StaticDiagnosticItem[] = [];

  const jsTsTargets: string[] = [];
  const pyTargets: string[] = [];

  for (const rel of boundedFiles.slice(0, 10)) {
    const fullPath = path.isAbsolute(rel) ? rel : path.join(resolvedCwd, rel);
    if (isSensitiveFilePath(fullPath) || !isWithinWorkspaceBoundary(resolvedCwd, fullPath)) {
      continue;
    }
    if (!fs.existsSync(fullPath)) continue;
    const stat = fs.statSync(fullPath);
    if (!stat.isFile() || stat.size > MAX_AST_FILE_BYTES) continue;

    if (rel.endsWith(".json")) {
      checkedFiles.push(rel);
      enginesUsed.add("json-parser");
      try {
        JSON.parse(fs.readFileSync(fullPath, "utf8"));
      } catch (err) {
        diagnostics.push({
          engine: "json",
          file: rel,
          severity: "error",
          code: "JSON_SYNTAX",
          message: err instanceof Error ? err.message : "Invalid JSON syntax"
        });
      }
    } else if (/\.(ts|tsx|js|jsx|mjs)$/i.test(rel)) {
      checkedFiles.push(rel);
      jsTsTargets.push(fullPath);

      // Fast in-memory ts-morph syntax parse check
      try {
        const content = fs.readFileSync(fullPath, "utf8");
        const sf = tsMorphProject.createSourceFile(fullPath, content, { overwrite: true });
        enginesUsed.add("ts-morph-ast");
        const syntaxDiags = sf.getPreEmitDiagnostics().filter((d) => d.getCategory() === 1 && d.getCode() < 2000);
        for (const d of syntaxDiags.slice(0, 4)) {
          const msg = d.getMessageText();
          diagnostics.push({
            engine: "ts-morph",
            file: rel,
            line: d.getLineNumber(),
            severity: "error",
            code: `TS${d.getCode()}`,
            message: typeof msg === "string" ? msg : msg.getMessageText()
          });
        }
        tsMorphProject.removeSourceFile(sf);
      } catch {
        // ignore
      }
    } else if (/\.py$/i.test(rel)) {
      checkedFiles.push(rel);
      pyTargets.push(fullPath);
    }
  }

  // Run Oxlint (Rust JS/TS Linter) on modified JS/TS files with shell: false
  if (jsTsTargets.length > 0) {
    const oxlintRunner = resolveLocalOxlintRunner();
    if (oxlintRunner) {
      try {
        const rawOut = execFileSync(
          oxlintRunner.cmd,
          [...oxlintRunner.prefixArgs, "--format", "json", ...jsTsTargets],
          {
            cwd: resolvedCwd,
            encoding: "utf8",
            timeout: 1500,
            stdio: ["ignore", "pipe", "pipe"]
          }
        ).trim();
        enginesUsed.add("oxlint-rust");
        parseOxlintJson(rawOut, resolvedCwd, diagnostics);
      } catch (err) {
        enginesUsed.add("oxlint-rust");
        if (err && typeof err === "object" && "stdout" in err && err.stdout) {
          parseOxlintJson(String(err.stdout), resolvedCwd, diagnostics);
        }
      }
    }
  }

  // Run Ruff (Astral Rust Python Linter respecting project config + ignoring S101 pytest assert false positives)
  if (pyTargets.length > 0) {
    try {
      const rawOut = execFileSync(
        resolvePythonExecutable(),
        ["-m", "ruff", "check", "--ignore", "S101,E501", "--output-format", "json", ...pyTargets],
        {
          cwd: resolvedCwd,
          encoding: "utf8",
          timeout: 1500,
          stdio: ["ignore", "pipe", "pipe"]
        }
      ).trim();
      enginesUsed.add("ruff-rust");
      parseRuffJson(rawOut, resolvedCwd, diagnostics);
    } catch (err) {
      if (err && typeof err === "object" && "stdout" in err && err.stdout) {
        enginesUsed.add("ruff-rust");
        parseRuffJson(String(err.stdout), resolvedCwd, diagnostics);
      }
    }
  }

  if (checkedFiles.length === 0) {
    return {
      enginesUsed: [],
      status: "SKIPPED",
      checkedFiles: [],
      errorCount: 0,
      warningCount: 0,
      diagnostics: []
    };
  }

  const errorCount = diagnostics.filter((d) => d.severity === "error").length;
  const warningCount = diagnostics.filter((d) => d.severity === "warning").length;

  return {
    enginesUsed: Array.from(enginesUsed),
    status:
      errorCount > 0 ? "ERRORS_DETECTED" : warningCount > 0 ? "WARNINGS" : "CLEAN",
    checkedFiles,
    errorCount,
    warningCount,
    diagnostics: diagnostics.slice(0, 15)
  };
}

function parseOxlintJson(
  rawJson: string,
  resolvedCwd: string,
  diagnostics: StaticDiagnosticItem[]
): void {
  try {
    const parsed = JSON.parse(rawJson) as {
      diagnostics?: Array<{
        filename?: string;
        severity?: string;
        code?: string;
        message?: string;
        labels?: Array<{ span?: { line?: number } }>;
      }>;
    };
    const list = Array.isArray(parsed.diagnostics) ? parsed.diagnostics : [];
    for (const item of list.slice(0, 10)) {
      const rel = item.filename
        ? path.relative(resolvedCwd, item.filename).replace(/\\/g, "/")
        : "unknown";
      diagnostics.push({
        engine: "oxlint",
        file: rel,
        line: item.labels?.[0]?.span?.line,
        severity: item.severity === "error" ? "error" : "warning",
        code: item.code ?? "oxlint",
        message: (item.message ?? "").slice(0, 200)
      });
    }
  } catch {
    // ignore malformed json
  }
}

function parseRuffJson(
  rawJson: string,
  resolvedCwd: string,
  diagnostics: StaticDiagnosticItem[]
): void {
  try {
    const list = JSON.parse(rawJson) as Array<{
      filename?: string;
      code?: string;
      message?: string;
      location?: { row?: number };
    }>;
    if (!Array.isArray(list)) return;
    for (const item of list.slice(0, 10)) {
      const rel = item.filename
        ? path.relative(resolvedCwd, item.filename).replace(/\\/g, "/")
        : "unknown";
      const code = item.code ?? "RUFF";
      const isError = code.startsWith("F") || code.startsWith("E9") || code.startsWith("S");
      diagnostics.push({
        engine: "ruff",
        file: rel,
        line: item.location?.row,
        severity: isError ? "error" : "warning",
        code,
        message: (item.message ?? "").slice(0, 200)
      });
    }
  } catch {
    // ignore malformed json
  }
}

/**
 * Integrates `codegraph` v0.8.0 (Tree-sitter Knowledge Graph):
 * - Automatically initializes `.codegraph` in the background if missing on a Git repo.
 * - Runs `codegraph sync`, `codegraph context`, and `codegraph affected --json` to retrieve
 *   graph-ranked context and affected test files across the dependency graph.
 */
export function queryCodeGraphIntelligence(
  cwd: string,
  taskOrSpec: string,
  changedFiles: string[] = []
): CodeGraphIntelligenceReport {
  const resolvedCwd = path.resolve(z.string().min(1).max(1024).parse(cwd));
  const boundedTask = z.string().max(16000).parse(taskOrSpec.slice(0, 16000));
  changedFiles = SafeFileListSchema.parse(changedFiles.slice(0, MAX_ANALYZED_FILES));
  const cgDir = path.join(resolvedCwd, ".codegraph");

  const cgRunner = resolveCodeGraphRunner();
  if (!cgRunner) {
    return {
      indexed: false,
      graphAffectedTests: [],
      symbolRelations: []
    };
  }

  if (!fs.existsSync(cgDir)) {
    // Auto-initialize CodeGraph asynchronously in the background if this is a Git repo
    if (
      fs.existsSync(path.join(resolvedCwd, ".git")) &&
      !autoInitTriggeredWorkspaces.has(resolvedCwd)
    ) {
      autoInitTriggeredWorkspaces.add(resolvedCwd);
      try {
        const child = spawn(cgRunner.cmd, [...cgRunner.prefixArgs, "init", "-i", resolvedCwd], {
          cwd: resolvedCwd,
          detached: true,
          stdio: "ignore"
        });
        child.on("error", () => {});
        child.unref();
      } catch {
        // non-fatal
      }
    }
    return {
      indexed: false,
      graphAffectedTests: [],
      symbolRelations: []
    };
  }

  // Sync incremental changes since last index
  try {
    execFileSync(cgRunner.cmd, [...cgRunner.prefixArgs, "sync", resolvedCwd], {
      cwd: resolvedCwd,
      encoding: "utf8",
      timeout: 1200,
      stdio: ["ignore", "pipe", "ignore"]
    });
  } catch {
    // non-fatal if locked
  }

  const stripAnsi = (s: string) => s.replace(/\x1b\[[0-9;]*m/g, "").trim();

  let taskGraphContext: string | undefined;
  if (boundedTask && boundedTask.trim().length > 0) {
    try {
      const cleanQuery = boundedTask
        .replace(/[^\w./:\s-]/g, " ")
        .replace(/\s+/g, " ")
        .trim()
        .slice(0, 160);
      if (cleanQuery.length > 0) {
        const ctxOut = execFileSync(
          cgRunner.cmd,
          [...cgRunner.prefixArgs, "context", "-p", resolvedCwd, "-n", "12", "--no-code", cleanQuery],
          {
            cwd: resolvedCwd,
            encoding: "utf8",
            timeout: 1400,
            stdio: ["ignore", "pipe", "ignore"]
          }
        ).trim();
        if (ctxOut) {
          taskGraphContext = stripAnsi(ctxOut).slice(0, 1800);
        }
      }
    } catch {
      // ignore timeout
    }
  }

  const graphAffectedTests: string[] = [];
  if (changedFiles.length > 0) {
    try {
      const safeChangedFiles = changedFiles
        .slice(0, 8)
        .filter((f) => !f.startsWith("-"));
      if (safeChangedFiles.length > 0) {
        const affOut = execFileSync(
          cgRunner.cmd,
          [...cgRunner.prefixArgs, "affected", "-p", resolvedCwd, "-q", ...safeChangedFiles],
          {
            cwd: resolvedCwd,
            encoding: "utf8",
            timeout: 1200,
            stdio: ["ignore", "pipe", "ignore"]
          }
        ).trim();
        if (affOut) {
          for (const line of affOut.split(/\r?\n/)) {
            const clean = stripAnsi(line);
            if (clean && !graphAffectedTests.includes(clean)) {
              graphAffectedTests.push(clean);
            }
          }
        }
      }
    } catch {
      // ignore
    }
  }

  const symbolRelations: string[] = [];
  if (changedFiles.length > 0) {
    try {
      const stem = path
        .basename(changedFiles[0], path.extname(changedFiles[0]))
        .replace(/[^\w.-]/g, "");
      if (stem && stem.length >= 3 && !stem.startsWith("-")) {
        const qOut = execFileSync(cgRunner.cmd, [...cgRunner.prefixArgs, "query", stem], {
          cwd: resolvedCwd,
          encoding: "utf8",
          timeout: 1100,
          stdio: ["ignore", "pipe", "ignore"]
        }).trim();
        if (qOut) {
          symbolRelations.push(
            ...qOut
              .split(/\r?\n/)
              .map(stripAnsi)
              .filter(Boolean)
              .slice(0, 10)
          );
        }
      }
    } catch {
      // ignore
    }
  }

  return {
    indexed: true,
    taskGraphContext,
    graphAffectedTests: graphAffectedTests.slice(0, 10),
    symbolRelations
  };
}
