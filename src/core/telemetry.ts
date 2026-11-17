import type { GateVerdict } from "./types.js";

export interface TelemetryEvent {
  operation: string;
  latencyMs: number;
  cached: boolean;
  inputTokens: number;
  outputTokens: number;
  costUsd: number;
  verdict?: GateVerdict;
  timestamp?: string;
}

export interface TelemetrySummary {
  totalCalls: number;
  apiCalls: number;
  cacheHits: number;
  cacheHitRate: number;
  avgApiLatencyMs: number;
  totalInputTokens: number;
  totalOutputTokens: number;
  totalCostUsd: number;
  verdictCounts: Record<GateVerdict, number>;
  recentEvents: TelemetryEvent[];
}

export class TelemetryTracker {
  private readonly events: TelemetryEvent[] = [];
  private readonly maxRecent: number;

  constructor(maxRecent = 50) {
    this.maxRecent = maxRecent;
  }

  public record(event: TelemetryEvent): void {
    this.events.push({
      ...event,
      timestamp: event.timestamp ?? new Date().toISOString()
    });
  }

  public getSummary(): TelemetrySummary {
    const totalCalls = this.events.length;
    let apiCalls = 0;
    let cacheHits = 0;
    let totalApiLatency = 0;
    let totalInputTokens = 0;
    let totalOutputTokens = 0;
    let totalCostUsd = 0;
    const verdictCounts: Record<GateVerdict, number> = {
      ALLOW: 0,
      ASK_USER: 0,
      BLOCK: 0
    };

    for (const ev of this.events) {
      if (ev.cached) {
        cacheHits += 1;
      } else {
        apiCalls += 1;
        totalApiLatency += ev.latencyMs;
      }
      totalInputTokens += ev.inputTokens;
      totalOutputTokens += ev.outputTokens;
      totalCostUsd += ev.costUsd;
      if (ev.verdict) {
        verdictCounts[ev.verdict] = (verdictCounts[ev.verdict] ?? 0) + 1;
      }
    }

    return {
      totalCalls,
      apiCalls,
      cacheHits,
      cacheHitRate: totalCalls > 0 ? Number((cacheHits / totalCalls).toFixed(3)) : 0,
      avgApiLatencyMs: apiCalls > 0 ? Math.round(totalApiLatency / apiCalls) : 0,
      totalInputTokens,
      totalOutputTokens,
      totalCostUsd: Number(totalCostUsd.toFixed(8)),
      verdictCounts,
      recentEvents: this.events.slice(-this.maxRecent)
    };
  }
}
