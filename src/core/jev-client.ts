import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { DecisionCache } from "./cache.js";
import { TelemetryTracker } from "./telemetry.js";
import type { GateVerdict, JevQuestion, JevRequest, JevResponse } from "./types.js";

export class JevApiError extends Error {
  public readonly code: string;
  public readonly statusCode?: number;

  constructor(message: string, code: string, statusCode?: number) {
    super(message);
    this.name = "JevApiError";
    this.code = code;
    this.statusCode = statusCode;
  }
}

export interface JevClientOptions {
  apiKey?: string;
  baseUrl?: string;
  model?: string;
  timeoutMs?: number;
  retryDelayMs?: number;
  configPath?: string;
  cache?: DecisionCache;
  telemetry?: TelemetryTracker;
  fetchImpl?: typeof fetch;
}

export interface EvaluateOptions {
  model?: string;
  skipCache?: boolean;
  operation?: string;
  verdict?: GateVerdict;
}

export interface EvaluateResult {
  response: JevResponse;
  latencyMs: number;
  cached: boolean;
}

export class JevClient {
  private readonly explicitApiKey?: string;
  private readonly baseUrl: string;
  private readonly defaultModel: string;
  private readonly timeoutMs: number;
  private readonly retryDelayMs: number;
  private readonly configPath: string;
  private readonly cache: DecisionCache;
  private readonly telemetry: TelemetryTracker;
  private readonly fetchImpl: typeof fetch;

  constructor(options: JevClientOptions = {}) {
    this.explicitApiKey = options.apiKey;
    this.baseUrl = (
      options.baseUrl ??
      process.env.JEV_BASE_URL ??
      "https://api.typesafe.ai/v1/systemone"
    ).replace(/\/+$/, "");
    this.defaultModel = options.model ?? process.env.JEV_MODEL ?? "jev-latest";
    this.timeoutMs = options.timeoutMs ?? Number(process.env.JEV_TIMEOUT_MS ?? 5000);
    this.retryDelayMs = options.retryDelayMs ?? 120;
    this.configPath =
      options.configPath ?? path.join(os.homedir(), ".mcp-jev", "config.json");
    this.cache = options.cache ?? new DecisionCache();
    this.telemetry = options.telemetry ?? new TelemetryTracker();
    this.fetchImpl = options.fetchImpl ?? globalThis.fetch;
  }

  public resolveApiKey(): string {
    if (this.explicitApiKey && this.explicitApiKey.trim().length > 0) {
      return this.explicitApiKey.trim();
    }
    const envKey = process.env.JEV_API_KEY ?? process.env.TYPESAFE_API_KEY;
    if (envKey && envKey.trim().length > 0) {
      return envKey.trim();
    }
    // Check local .env file if present
    const localEnvPath = path.resolve(process.cwd(), ".env");
    if (this.explicitApiKey === undefined && fs.existsSync(localEnvPath)) {
      try {
        const content = fs.readFileSync(localEnvPath, "utf8");
        const match = content.match(/^(?:JEV_API_KEY|TYPESAFE_API_KEY)\s*=\s*["']?([^\s"'\r\n]+)["']?/m);
        if (match?.[1]) {
          return match[1].trim();
        }
      } catch {
        // Ignore read error
      }
    }
    // Check ~/.mcp-jev/config.json
    if (fs.existsSync(this.configPath)) {
      try {
        const parsed = JSON.parse(fs.readFileSync(this.configPath, "utf8")) as {
          apiKey?: string;
        };
        if (parsed.apiKey && parsed.apiKey.trim().length > 0) {
          return parsed.apiKey.trim();
        }
      } catch {
        // Ignore parse error
      }
    }
    throw new JevApiError(
      "Missing Jev API key. Set JEV_API_KEY (or TYPESAFE_API_KEY) environment variable, or run `npx mcp-jev setup --api-key <key>`.",
      "MISSING_API_KEY"
    );
  }

  public async evaluate(
    state: unknown,
    questions: Record<string, JevQuestion>,
    options: EvaluateOptions = {}
  ): Promise<EvaluateResult> {
    const startTime = Date.now();
    const model = options.model ?? this.defaultModel;
    const normalizedQuestions = this.normalizeQuestions(questions);
    const requestPayload: JevRequest = {
      model,
      state,
      questions: normalizedQuestions
    };

    const cacheKey = this.cache.computeKey(requestPayload);
    if (!options.skipCache) {
      const cachedResponse = this.cache.get(cacheKey);
      if (cachedResponse) {
        const latencyMs = Date.now() - startTime;
        this.telemetry.record({
          operation: options.operation ?? "jev_evaluate",
          latencyMs,
          cached: true,
          inputTokens: 0,
          outputTokens: 0,
          costUsd: 0,
          verdict: options.verdict
        });
        return {
          response: cachedResponse,
          latencyMs,
          cached: true
        };
      }
    }

    const apiKey = this.resolveApiKey();
    const rawResponse = await this.sendWithRetry(apiKey, requestPayload);
    const response = this.normalizeResponse(rawResponse);
    const latencyMs = Date.now() - startTime;

    if (!options.skipCache) {
      this.cache.set(cacheKey, response);
    }

    this.telemetry.record({
      operation: options.operation ?? "jev_evaluate",
      latencyMs,
      cached: false,
      inputTokens: response.usage?.input_tokens ?? 0,
      outputTokens: response.usage?.output_tokens ?? 0,
      costUsd: response.usage?.cost ?? 0,
      verdict: options.verdict
    });

    return {
      response,
      latencyMs,
      cached: false
    };
  }

  private normalizeQuestions(
    questions: Record<string, JevQuestion>
  ): Record<string, JevQuestion> {
    const out: Record<string, JevQuestion> = {};
    for (const [key, q] of Object.entries(questions)) {
      if (q.type === "score") {
        let criteriaList: string[];
        if (Array.isArray(q.criteria) && q.criteria.length >= 2) {
          criteriaList = q.criteria;
        } else if (q.criteria && typeof q.criteria === "object") {
          criteriaList = Object.entries(q.criteria).map(([k, v]) => `${k}: ${v}`);
        } else {
          criteriaList = [
            "1: Very Low",
            "2: Low",
            "3: Moderate",
            "4: High",
            "5: Very High"
          ];
        }
        out[key] = {
          type: "score",
          instructions: q.instructions,
          criteria: criteriaList
        };
      } else {
        out[key] = q;
      }
    }
    return out;
  }

  private normalizeResponse(raw: JevResponse): JevResponse {
    const normalizedAnswers: JevResponse["answers"] = {};
    for (const [key, ans] of Object.entries(raw.answers ?? {})) {
      if (ans.type === "choice") {
        const chosen = ans.choice ?? ans.selected ?? "";
        normalizedAnswers[key] = {
          ...ans,
          choice: chosen,
          selected: chosen
        };
      } else if (ans.type === "score") {
        // Jev 1.14 returns score in [0, 1] alongside a legend map; normalize to 1..5 scale if in [0, 1] with legend
        const rawScore = typeof ans.score === "number" ? ans.score : 0;
        const scaledScore =
          ans.legend && rawScore >= 0 && rawScore <= 1
            ? Number((1 + rawScore * 4).toFixed(2))
            : rawScore;
        normalizedAnswers[key] = {
          ...ans,
          score: scaledScore
        };
      } else {
        normalizedAnswers[key] = ans;
      }
    }

    const inputTokens = raw.usage?.input_tokens ?? 0;
    const outputTokens = raw.usage?.output_tokens ?? 0;
    // TypeSafe Jev pricing: $0.042 per 1M input tokens, $0 output tokens
    const computedCost =
      raw.usage?.cost !== undefined
        ? raw.usage.cost
        : Number(((inputTokens / 1_000_000) * 0.042).toFixed(8));

    return {
      ...raw,
      answers: normalizedAnswers,
      usage: {
        input_tokens: inputTokens,
        output_tokens: outputTokens,
        cost: computedCost
      }
    };
  }

  public recordVerdict(verdict: GateVerdict, operation: string): void {
    this.telemetry.record({
      operation,
      latencyMs: 0,
      cached: true,
      inputTokens: 0,
      outputTokens: 0,
      costUsd: 0,
      verdict
    });
  }

  public getTelemetry(): TelemetryTracker {
    return this.telemetry;
  }

  public getCache(): DecisionCache {
    return this.cache;
  }

  private async sendWithRetry(apiKey: string, payload: JevRequest): Promise<JevResponse> {
    let lastError: unknown;
    for (let attempt = 0; attempt < 2; attempt += 1) {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), this.timeoutMs);

      try {
        const res = await this.fetchImpl(this.baseUrl, {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            Authorization: `Bearer ${apiKey}`
          },
          body: JSON.stringify(payload),
          signal: controller.signal
        });

        if (res.ok) {
          const data = (await res.json()) as JevResponse;
          return data;
        }

        const errText = await res.text().catch(() => "");
        if ((res.status === 429 || res.status >= 500) && attempt === 0) {
          await new Promise((r) => setTimeout(r, this.retryDelayMs));
          continue;
        }

        throw new JevApiError(
          `Jev API returned HTTP ${res.status}: ${errText.slice(0, 300)}`,
          `HTTP_${res.status}`,
          res.status
        );
      } catch (err) {
        if (err instanceof JevApiError) {
          throw err;
        }
        lastError = err;
        if (attempt === 0) {
          await new Promise((r) => setTimeout(r, this.retryDelayMs));
          continue;
        }
      } finally {
        clearTimeout(timer);
      }
    }

    throw new JevApiError(
      `Network error communicating with Jev API: ${
        lastError instanceof Error ? lastError.message : String(lastError)
      }`,
      "NETWORK_ERROR"
    );
  }
}
