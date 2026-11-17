import test from "node:test";
import assert from "node:assert/strict";
import { JevClient, JevApiError } from "../src/core/jev-client.js";
import type { JevResponse } from "../src/core/types.js";

test("JevClient sends POST to /v1/systemone, caches responses, and records telemetry", async () => {
  let fetchCount = 0;
  const mockFetch: typeof fetch = async (input, init) => {
    fetchCount += 1;
    assert.equal(String(input), "https://api.typesafe.ai/v1/systemone");
    assert.equal(init?.method, "POST");
    const headers = init?.headers as Record<string, string>;
    assert.equal(headers["Authorization"], "Bearer jev_live_test_key");

    const body = JSON.parse(String(init?.body));
    assert.equal(body.model, "jev-latest");
    assert.ok(body.questions.is_safe);

    const payload: JevResponse = {
      model: "jev-1.14.0",
      answers: {
        is_safe: { type: "noul", noul: 0.97 }
      },
      usage: { input_tokens: 120, output_tokens: 15, cost: 0.000005 }
    };

    return new Response(JSON.stringify(payload), {
      status: 200,
      headers: { "Content-Type": "application/json" }
    });
  };

  const client = new JevClient({
    apiKey: "jev_live_test_key",
    fetchImpl: mockFetch
  });

  // First call hits network
  const first = await client.evaluate(
    { command: "git status" },
    { is_safe: { type: "noul", instructions: "Is this command safe?" } },
    { operation: "test_guard" }
  );

  assert.equal(first.cached, false);
  assert.equal( fetchCount, 1);
  assert.equal(first.response.answers.is_safe.type, "noul");
  if (first.response.answers.is_safe.type === "noul") {
    assert.equal(first.response.answers.is_safe.noul, 0.97);
  }

  // Second identical call hits SHA-256 cache without network request
  const second = await client.evaluate(
    { command: "git status" },
    { is_safe: { type: "noul", instructions: "Is this command safe?" } },
    { operation: "test_guard" }
  );

  assert.equal(second.cached, true);
  assert.equal(fetchCount, 1);

  const stats = client.getTelemetry().getSummary();
  assert.equal(stats.totalCalls, 2);
  assert.equal(stats.cacheHits, 1);
  assert.equal(stats.apiCalls, 1);
});

test("JevClient retries once on 503 transient failure and succeeds", async () => {
  let attempts = 0;
  const mockFetch: typeof fetch = async () => {
    attempts += 1;
    if (attempts === 1) {
      return new Response("Service Unavailable", { status: 503 });
    }
    const payload: JevResponse = {
      model: "jev-1.14.0",
      answers: { ok: { type: "noul", noul: 0.91 } }
    };
    return new Response(JSON.stringify(payload), { status: 200 });
  };

  const client = new JevClient({
    apiKey: "jev_live_retry_key",
    fetchImpl: mockFetch,
    retryDelayMs: 5
  });

  const res = await client.evaluate(
    "state",
    { ok: { type: "noul", instructions: "Ok?" } }
  );
  assert.equal(attempts, 2);
  assert.equal(res.response.answers.ok.type, "noul");
});

test("JevClient throws JevApiError when API key is missing", async () => {
  const originalJev = process.env.JEV_API_KEY;
  const originalTypesafe = process.env.TYPESAFE_API_KEY;
  delete process.env.JEV_API_KEY;
  delete process.env.TYPESAFE_API_KEY;

  try {
    const client = new JevClient({ apiKey: "", configPath: "nonexistent-config-path.json" });
    await assert.rejects(
      async () => {
        await client.evaluate("x", { q: { type: "noul", instructions: "Test?" } });
      },
      (err: unknown) => err instanceof JevApiError && err.code === "MISSING_API_KEY"
    );
  } finally {
    if (originalJev !== undefined) process.env.JEV_API_KEY = originalJev;
    if (originalTypesafe !== undefined) process.env.TYPESAFE_API_KEY = originalTypesafe;
  }
});
