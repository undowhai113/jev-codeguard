import test from "node:test";
import assert from "node:assert/strict";
import { DecisionCache } from "../src/core/cache.js";
import { TelemetryTracker } from "../src/core/telemetry.js";
import type { JevRequest, JevResponse } from "../src/core/types.js";

test("DecisionCache generates deterministic SHA-256 keys regardless of object key order", () => {
  const cache = new DecisionCache({ maxEntries: 10, ttlMs: 60_000 });

  const reqA: JevRequest = {
    model: "jev-latest",
    state: { b: 2, a: 1 },
    questions: {
      q2: { type: "noul", instructions: "Second?" },
      q1: { type: "noul", instructions: "First?" }
    }
  };

  const reqB: JevRequest = {
    model: "jev-latest",
    state: { a: 1, b: 2 },
    questions: {
      q1: { type: "noul", instructions: "First?" },
      q2: { type: "noul", instructions: "Second?" }
    }
  };

  const keyA = cache.computeKey(reqA);
  const keyB = cache.computeKey(reqB);
  assert.equal(keyA, keyB);
  assert.equal(keyA.length, 64);
});

test("DecisionCache stores, retrieves, and evicts entries when capacity is exceeded", () => {
  const cache = new DecisionCache({ maxEntries: 2, ttlMs: 60_000 });
  const mockResponse: JevResponse = {
    model: "jev-1.14.0",
    answers: {
      safe: { type: "noul", noul: 0.96 }
    },
    usage: { input_tokens: 50, output_tokens: 10, cost: 0.0000021 }
  };

  cache.set("k1", mockResponse);
  cache.set("k2", mockResponse);
  assert.deepEqual(cache.get("k1"), mockResponse);

  // Inserting k3 should evict k2 (since k1 was just accessed)
  cache.set("k3", mockResponse);
  assert.equal(cache.get("k2"), undefined);
  assert.deepEqual(cache.get("k1"), mockResponse);
  assert.deepEqual(cache.get("k3"), mockResponse);
});

test("TelemetryTracker aggregates latency, cache hits, cost, and gate decisions", () => {
  const telemetry = new TelemetryTracker();

  telemetry.record({
    operation: "jev_guard_action",
    latencyMs: 140,
    cached: false,
    inputTokens: 200,
    outputTokens: 20,
    costUsd: 0.0000084,
    verdict: "ALLOW"
  });

  telemetry.record({
    operation: "jev_guard_action",
    latencyMs: 1,
    cached: true,
    inputTokens: 0,
    outputTokens: 0,
    costUsd: 0,
    verdict: "ALLOW"
  });

  telemetry.record({
    operation: "jev_audit_code",
    latencyMs: 190,
    cached: false,
    inputTokens: 500,
    outputTokens: 40,
    costUsd: 0.000021,
    verdict: "BLOCK"
  });

  const summary = telemetry.getSummary();
  assert.equal(summary.totalCalls, 3);
  assert.equal(summary.cacheHits, 1);
  assert.equal(summary.apiCalls, 2);
  assert.equal(summary.totalInputTokens, 700);
  assert.equal(summary.verdictCounts.ALLOW, 2);
  assert.equal(summary.verdictCounts.BLOCK, 1);
  assert.ok(summary.totalCostUsd > 0.000029);
});
