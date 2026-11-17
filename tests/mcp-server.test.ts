import test from "node:test";
import assert from "node:assert/strict";
import os from "node:os";
import path from "node:path";
import fs from "node:fs";
import { McpJevDispatcher, createMcpJevServer } from "../src/mcp/server.js";
import { JevClient } from "../src/core/jev-client.js";
import { budgetMultiFileDiff } from "../src/core/git-collector.js";
import type { JevResponse } from "../src/core/types.js";

test("McpJevDispatcher executes jev_guard_action, jev_prune_context, jev_route_task, and jev_stats", async () => {
  const tmpEvents = path.join(os.tmpdir(), `jev-mcp-test-${Date.now()}.jsonl`);
  process.env.JEV_EVENTS_FILE = tmpEvents;
  const mockFetch: typeof fetch = async (_url, init) => {
    const body = JSON.parse(String(init?.body));
    const qKeys = Object.keys(body.questions);

    const answers: JevResponse["answers"] = {};
    for (const k of qKeys) {
      const q = body.questions[k];
      if (q.type === "noul") {
        answers[k] = { type: "noul", noul: k === "is_safe_to_execute" || k === "item_0" ? 0.94 : 0.05 };
      } else if (q.type === "score") {
        answers[k] = { type: "score", score: 1.5, probabilities: { "1": 0.5, "2": 0.5 } };
      } else if (q.type === "choice") {
        const firstOpt = Object.keys(q.criteria)[0] ?? "allow_silently";
        answers[k] = {
          type: "choice",
          selected: firstOpt,
          probabilities: { [firstOpt]: 0.9 }
        };
      }
    }

    return new Response(
      JSON.stringify({
        model: "jev-1.14.0",
        answers,
        usage: { input_tokens: 100, output_tokens: 20, cost: 0.0000042 }
      }),
      { status: 200 }
    );
  };

  let fetchCalls = 0;
  const countingFetch: typeof fetch = async (url, init) => {
    fetchCalls += 1;
    return mockFetch(url, init);
  };
  const client = new JevClient({ apiKey: "jev_test_mcp", fetchImpl: countingFetch });
  const dispatcher = new McpJevDispatcher(client);

  const guardRes = await dispatcher.guardAction({
    exact_command: "npm test",
    context: "Running unit tests in workspace"
  });
  assert.equal(guardRes.decision.verdict, "ALLOW");
  assert.equal(guardRes.commandShape.looksLikeProse, false);
  assert.equal(fetchCalls, 1);

  // A self-written description (as Codex sent in the real log) is refused without scoring.
  const proseRes = await dispatcher.guardAction({
    exact_command:
      "Commit only four documentation files on the existing branch. No push, merge or runtime actions.",
    context: "Owner assigned shared-memory checkpoint"
  });
  assert.equal(proseRes.decision.verdict, "ASK_USER");
  assert.equal(proseRes.commandShape.looksLikeProse, true);
  assert.ok(proseRes.decision.remediation.some((r) => r.includes("exact_command")));
  assert.equal(fetchCalls, 1, "prose must not be sent to the Jev API");

  const pruneRes = await dispatcher.pruneContext({
    task: "Update authentication middleware",
    candidates: [
      { id: "src/auth.ts", summary: "Auth middleware" },
      { id: "README.md", summary: "Project readme" }
    ],
    threshold: 0.6
  });
  assert.equal(pruneRes.keptCount, 1);
  assert.equal(pruneRes.kept[0].item.id, "src/auth.ts");

  const routeRes = await dispatcher.routeTask({
    task_description: "Implement red-green unit test for token parser"
  });
  assert.ok(routeRes.strategy);

  const stats = dispatcher.getStats();
  assert.equal(stats.totalCalls, 3);

  const mcpServer = createMcpJevServer(client);
  assert.ok(mcpServer);
  if (fs.existsSync(tmpEvents)) {
    fs.unlinkSync(tmpEvents);
  }
  delete process.env.JEV_EVENTS_FILE;
});

test("budgetMultiFileDiff preserves all files at the end of the alphabet when one early file is huge", () => {
  const hugeA = `diff --git a/app/a.ts b/app/a.ts\n+${"A".repeat(10000)}`;
  const smallZ = `diff --git a/tests/z.test.ts b/tests/z.test.ts\n+expect(true).toBe(true);`;
  const raw = `${hugeA}\n${smallZ}`;
  const stat = " app/a.ts | 100 +++\n tests/z.test.ts | 1 +";

  const out = budgetMultiFileDiff(raw, stat, 4000);
  assert.ok(out.includes("=== GIT DIFF STAT ==="));
  assert.ok(out.includes("diff --git a/app/a.ts b/app/a.ts"));
  assert.ok(out.includes("diff --git a/tests/z.test.ts b/tests/z.test.ts"));
  assert.ok(out.includes("+expect(true).toBe(true);"));
});
