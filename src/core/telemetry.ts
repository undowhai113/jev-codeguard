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
  private readonly recentEvents: TelemetryEvent[] = [];
  private readonly maxRecent: number;
  private totalCalls = 0;
  private apiCalls = 0;
  private cacheHits = 0;
  private totalApiLatency = 0;
  private totalInputTokens = 0;
  private totalOutputTokens = 0;
  private totalCostUsd = 0;
  private readonly verdictCounts: Record<GateVerdict, number> = {
    ALLOW: 0,
    ASK_USER: 0,
    BLOCK: 0
  };

  constructor(maxRecent = 50) {
    this.maxRecent = Math.max(1, maxRecent);
  }

  public record(event: TelemetryEvent): void {
    const normalized: TelemetryEvent = {
      ...event,
      timestamp: event.timestamp ?? new Date().toISOString()
    };
    this.totalCalls += 1;
    if (normalized.cached) {
      this.cacheHits += 1;
    } else {
      this.apiCalls += 1;
      this.totalApiLatency += normalized.latencyMs;
    }
    this.totalInputTokens += normalized.inputTokens;
    this.totalOutputTokens += normalized.outputTokens;
    this.totalCostUsd += normalized.costUsd;
    if (normalized.verdict) {
      this.verdictCounts[normalized.verdict] = (this.verdictCounts[normalized.verdict] ?? 0) + 1;
    }

    this.recentEvents.push(normalized);
    if (this.recentEvents.length > this.maxRecent) {
      this.recentEvents.splice(0, this.recentEvents.length - this.maxRecent);
    }
  }

  public getSummary(): TelemetrySummary {
    return {
      totalCalls: this.totalCalls,
      apiCalls: this.apiCalls,
      cacheHits: this.cacheHits,
      cacheHitRate:
        this.totalCalls > 0 ? Number((this.cacheHits / this.totalCalls).toFixed(3)) : 0,
      avgApiLatencyMs:
        this.apiCalls > 0 ? Math.round(this.totalApiLatency / this.apiCalls) : 0,
      totalInputTokens: this.totalInputTokens,
      totalOutputTokens: this.totalOutputTokens,
      totalCostUsd: Number(this.totalCostUsd.toFixed(8)),
      verdictCounts: { ...this.verdictCounts },
      recentEvents: [...this.recentEvents]
    };
  }
}
