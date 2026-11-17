import { createHash } from "node:crypto";
import type { JevRequest, JevResponse } from "./types.js";

export interface DecisionCacheOptions {
  maxEntries?: number;
  ttlMs?: number;
}

interface CacheEntry {
  response: JevResponse;
  expiresAt: number;
}

function canonicalize(value: unknown): unknown {
  if (Array.isArray(value)) {
    return value.map(canonicalize);
  }
  if (value !== null && typeof value === "object") {
    const sortedKeys = Object.keys(value as Record<string, unknown>).sort();
    const out: Record<string, unknown> = {};
    for (const key of sortedKeys) {
      out[key] = canonicalize((value as Record<string, unknown>)[key]);
    }
    return out;
  }
  return value;
}

export class DecisionCache {
  private readonly maxEntries: number;
  private readonly ttlMs: number;
  private readonly store = new Map<string, CacheEntry>();

  constructor(options: DecisionCacheOptions = {}) {
    this.maxEntries = options.maxEntries ?? 500;
    this.ttlMs = options.ttlMs ?? 10 * 60 * 1000;
  }

  public computeKey(request: JevRequest): string {
    const normalized = JSON.stringify(canonicalize(request));
    return createHash("sha256").update(normalized).digest("hex");
  }

  public get(key: string): JevResponse | undefined {
    const entry = this.store.get(key);
    if (!entry) {
      return undefined;
    }
    if (Date.now() > entry.expiresAt) {
      this.store.delete(key);
      return undefined;
    }
    // Refresh LRU order
    this.store.delete(key);
    this.store.set(key, entry);
    return entry.response;
  }

  public set(key: string, response: JevResponse): void {
    if (this.store.has(key)) {
      this.store.delete(key);
    } else if (this.store.size >= this.maxEntries) {
      const oldestKey = this.store.keys().next().value;
      if (oldestKey !== undefined) {
        this.store.delete(oldestKey);
      }
    }
    this.store.set(key, {
      response,
      expiresAt: Date.now() + this.ttlMs
    });
  }

  public clear(): void {
    this.store.clear();
  }

  public size(): number {
    return this.store.size;
  }
}
