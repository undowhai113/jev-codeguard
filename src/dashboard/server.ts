import crypto from "node:crypto";
import http from "node:http";
import { z } from "zod";
import {
  clearSessionEvents,
  getEventsFilePath,
  readSessionEvents,
  type JevSessionEvent
} from "../core/event-log.js";
import {
  listProjectBrainProfiles,
  recordProjectFeedbackRule,
  removeProjectFeedbackRule
} from "../core/context-enricher.js";
import { McpJevDispatcher } from "../mcp/server.js";

const MAX_BODY_BYTES = 4096;
const MAX_SSE_CLIENTS = 32;
const MAX_EVENTS_LIMIT = 200;

const SimulatePayloadSchema = z.object({
  agent: z.enum(["Codex", "Gemini"]).optional().default("Codex"),
  lang: z.enum(["en", "vi"]).optional().default("en"),
  scenario: z.string().max(120).optional()
});

const FeedbackPayloadSchema = z.object({
  workspaceName: z.string().min(1).max(120),
  workspacePath: z.string().max(400).optional(),
  tool: z.string().max(80).optional(),
  feedbackType: z
    .enum(["CORRECT", "FALSE_POSITIVE_OVERRIDE", "CUSTOM_RULE"])
    .default("FALSE_POSITIVE_OVERRIDE"),
  rule: z.string().min(3).max(500),
  eventId: z.string().max(80).optional()
});

const DeleteRulePayloadSchema = z.object({
  workspaceName: z.string().min(1).max(120),
  ruleId: z.string().min(1).max(80)
});

function isTrustedLocalRequest(
  req: http.IncomingMessage,
  port: number,
  expectedCsrfToken: string
): boolean {
  const remote = req.socket.remoteAddress ?? "";
  if (remote !== "127.0.0.1" && remote !== "::1" && remote !== "::ffff:127.0.0.1") {
    return false;
  }
  // Defend against DNS Rebinding attacks by enforcing strict localhost Host header
  const host = (req.headers.host ?? "").toLowerCase();
  const allowedHosts = new Set([
    `localhost:${port}`,
    `127.0.0.1:${port}`,
    `[::1]:${port}`
  ]);
  if (!allowedHosts.has(host)) {
    return false;
  }
  const origin = req.headers.origin;
  if (origin) {
    const allowedOrigins = new Set([
      `http://localhost:${port}`,
      `http://127.0.0.1:${port}`,
      `http://[::1]:${port}`
    ]);
    if (!allowedOrigins.has(origin)) {
      return false;
    }
  }
  if (req.method === "POST" || req.method === "DELETE") {
    const provided = String(req.headers["x-jev-csrf"] ?? "");
    const expectedBuf = Buffer.from(expectedCsrfToken, "utf8");
    const providedBuf = Buffer.from(provided, "utf8");
    if (
      providedBuf.length !== expectedBuf.length ||
      !crypto.timingSafeEqual(providedBuf, expectedBuf)
    ) {
      return false;
    }
  }
  return true;
}

function readBoundedBody(req: http.IncomingMessage, maxBytes = MAX_BODY_BYTES): Promise<string> {
  return new Promise((resolve, reject) => {
    let total = 0;
    let body = "";
    req.setEncoding("utf8");
    req.on("data", (chunk: string) => {
      total += Buffer.byteLength(chunk, "utf8");
      if (total > maxBytes) {
        req.destroy();
        reject(new Error("Payload too large"));
        return;
      }
      body += chunk;
    });
    req.on("end", () => resolve(body));
    req.on("error", (err) => reject(err));
  });
}

export interface DashboardServerOptions {
  port?: number;
}

export function startDashboardServer(options: DashboardServerOptions = {}): Promise<{
  port: number;
  url: string;
  server: http.Server;
}> {
  const port = options.port ?? Number(process.env.JEV_DASHBOARD_PORT || 4399);
  const csrfToken = crypto.randomBytes(24).toString("hex");
  const dispatcher = new McpJevDispatcher();
  const sseClients = new Set<http.ServerResponse>();

  let lastSeenId: string | null = readSessionEvents(1)[0]?.id ?? null;

  const watcherInterval = setInterval(() => {
    const recent = readSessionEvents(10);
    if (recent.length === 0) return;

    if (lastSeenId === null) {
      lastSeenId = recent[0].id;
      broadcastEvent(recent[0]);
      return;
    }

    const newEvents: JevSessionEvent[] = [];
    for (const evt of recent) {
      if (evt.id === lastSeenId) break;
      newEvents.push(evt);
    }

    if (newEvents.length > 0) {
      lastSeenId = recent[0].id;
      for (const evt of newEvents.reverse()) {
        broadcastEvent(evt);
      }
    }
  }, 350);

  watcherInterval.unref();

  function broadcastEvent(evt: JevSessionEvent): void {
    const payload = `data: ${JSON.stringify({ type: "new_event", event: evt })}\n\n`;
    for (const client of sseClients) {
      try {
        client.write(payload);
      } catch {
        sseClients.delete(client);
      }
    }
  }

  const server = http.createServer(async (req, res) => {
    const addr = server.address();
    const activePort = typeof addr === "object" && addr ? addr.port : port;
    const urlObj = new URL(req.url ?? "/", `http://localhost:${activePort}`);

    res.setHeader("X-Content-Type-Options", "nosniff");
    res.setHeader("X-Frame-Options", "DENY");
    res.setHeader("Referrer-Policy", "no-referrer");
    res.setHeader("Cache-Control", "private, no-store");

    if (!isTrustedLocalRequest(req, activePort, csrfToken)) {
      res.writeHead(403, { "Content-Type": "application/json; charset=utf-8" });
      res.end(JSON.stringify({ error: "Forbidden: local same-origin access with valid CSRF token required" }));
      return;
    }

    if (req.method === "GET" && urlObj.pathname === "/api/events") {
      const rawLimit = Number.parseInt(urlObj.searchParams.get("limit") ?? "100", 10);
      const boundedLimit = Number.isFinite(rawLimit)
        ? Math.min(Math.max(1, rawLimit), MAX_EVENTS_LIMIT)
        : 100;
      const events = readSessionEvents(boundedLimit);
      res.writeHead(200, { "Content-Type": "application/json; charset=utf-8" });
      res.end(
        JSON.stringify({
          events,
          eventsFilePath: getEventsFilePath(),
          stats: computeAggregateStats(events)
        })
      );
      return;
    }

    if (req.method === "DELETE" && urlObj.pathname === "/api/events") {
      clearSessionEvents();
      lastSeenId = null;
      res.writeHead(200, { "Content-Type": "application/json; charset=utf-8" });
      res.end(JSON.stringify({ ok: true }));
      return;
    }

    if (req.method === "GET" && urlObj.pathname === "/api/projects") {
      const profiles = listProjectBrainProfiles();
      res.writeHead(200, { "Content-Type": "application/json; charset=utf-8" });
      res.end(JSON.stringify({ ok: true, profiles }));
      return;
    }

    if (req.method === "POST" && urlObj.pathname === "/api/feedback") {
      try {
        const rawBody = await readBoundedBody(req, MAX_BODY_BYTES);
        const jsonBody: unknown = rawBody.trim() ? JSON.parse(rawBody) : {};
        const validated = FeedbackPayloadSchema.parse(jsonBody);
        const saved = recordProjectFeedbackRule(validated);
        res.writeHead(200, { "Content-Type": "application/json; charset=utf-8" });
        res.end(JSON.stringify({ ok: true, rule: saved }));
      } catch (err) {
        res.writeHead(400, { "Content-Type": "application/json; charset=utf-8" });
        res.end(
          JSON.stringify({
            ok: false,
            error: err instanceof Error ? err.message : "Invalid feedback payload"
          })
        );
      }
      return;
    }

    if (req.method === "DELETE" && urlObj.pathname === "/api/projects/rule") {
      try {
        const rawBody = await readBoundedBody(req, MAX_BODY_BYTES);
        const jsonBody: unknown = rawBody.trim() ? JSON.parse(rawBody) : {};
        const validated = DeleteRulePayloadSchema.parse(jsonBody);
        const removed = removeProjectFeedbackRule(validated.workspaceName, validated.ruleId);
        res.writeHead(200, { "Content-Type": "application/json; charset=utf-8" });
        res.end(JSON.stringify({ ok: removed }));
      } catch (err) {
        res.writeHead(400, { "Content-Type": "application/json; charset=utf-8" });
        res.end(
          JSON.stringify({
            ok: false,
            error: err instanceof Error ? err.message : "Invalid delete payload"
          })
        );
      }
      return;
    }

    if (req.method === "POST" && urlObj.pathname === "/api/simulate") {
      try {
        const rawBody = await readBoundedBody(req, MAX_BODY_BYTES);
        const jsonBody: unknown = rawBody.trim() ? JSON.parse(rawBody) : {};
        const validated = SimulatePayloadSchema.parse(jsonBody);
        const agent = validated.agent;
        const isVi = validated.lang === "vi";

        if (agent === "Codex") {
          await dispatcher.autopilotDecide({
            agent: "Codex",
            working_directory: process.cwd(),
            question: isVi
              ? "Xử lý race condition khi trừ tồn kho vật tư (Stock Adjustment) trong dự án acme-inventory-api bằng phương án nào?"
              : "How should we prevent concurrent stock-adjustment race conditions in acme-inventory-api?",
            options: isVi
              ? {
                  optimistic_prisma_tx:
                    "Dùng Prisma interactive transaction ($transaction) kết hợp điều kiện WHERE version / stock >= quantity (an toàn, không cần thêm infra)",
                  redis_redlock:
                    "Dựng thêm cụm Redis cluster và dùng Redlock distributed lock cho mọi thao tác kho",
                  ignore_race: "Kiểm tra số lượng tồn kho trên React state ở phía trình duyệt"
                }
              : {
                  optimistic_prisma_tx:
                    "Use an interactive Prisma $transaction with atomic WHERE stock >= quantity guard (zero extra infrastructure)",
                  redis_redlock:
                    "Provision a dedicated Redis cluster and wrap every inventory mutation in Redlock",
                  client_side_check: "Validate remaining stock count in browser React state only"
                },
            context: isVi
              ? "Next.js + Prisma PostgreSQL monorepo (acme-inventory-api), ưu tiên bảo mật và gọn nhẹ."
              : "Next.js + Prisma PostgreSQL monorepo (acme-inventory-api), prioritizing safety and operational simplicity."
          });
        } else {
          await dispatcher.autopilotDecide({
            agent: "Gemini",
            working_directory: process.cwd(),
            question: isVi
              ? "Truyền sự kiện real-time từ MCP-Jev sang giao diện SaaS Dashboard bằng giao thức nào?"
              : "Which real-time transport should stream MCP-Jev events to the local developer dashboard?",
            options: isVi
              ? {
                  sse_jsonl_stream:
                    "Server-Sent Events (SSE) kết hợp file ledger ~/.mcp-jev/events.jsonl (gọn nhẹ, 0 dependency ngoài, tự động reconnect)",
                  socket_io_redis:
                    "Cài đặt Socket.IO + Redis PubSub adapter nặng nề cho local tool",
                  long_polling_5s: "HTTP polling mỗi 5 giây gây trễ hiển thị"
                }
              : {
                  sse_jsonl_stream:
                    "Native Server-Sent Events (SSE) backed by ~/.mcp-jev/events.jsonl (zero external dependencies, built-in browser reconnect)",
                  socket_io_redis:
                    "Bundle Socket.IO + Redis PubSub adapter inside a local CLI package",
                  long_polling_5s: "5-second HTTP interval polling with stale UI updates"
                },
            context: "Local TypeScript MCP server + real-time developer dashboard."
          });
        }

        const latest = readSessionEvents(1)[0];
        res.writeHead(200, { "Content-Type": "application/json; charset=utf-8" });
        res.end(JSON.stringify({ ok: true, event: latest }));
      } catch (err) {
        res.writeHead(400, { "Content-Type": "application/json; charset=utf-8" });
        res.end(
          JSON.stringify({
            ok: false,
            error: err instanceof Error ? err.message : "Invalid request payload"
          })
        );
      }
      return;
    }

    if (req.method === "GET" && urlObj.pathname === "/api/stream") {
      if (sseClients.size >= MAX_SSE_CLIENTS) {
        res.writeHead(429, { "Content-Type": "application/json; charset=utf-8" });
        res.end(JSON.stringify({ error: "Too many active SSE connections" }));
        return;
      }
      res.writeHead(200, {
        "Content-Type": "text/event-stream; charset=utf-8",
        "Cache-Control": "no-cache, no-transform",
        Connection: "keep-alive"
      });
      res.write(`data: ${JSON.stringify({ type: "connected", timestamp: new Date().toISOString() })}\n\n`);
      sseClients.add(res);
      req.on("close", () => {
        sseClients.delete(res);
      });
      return;
    }

    if (req.method === "GET" && (urlObj.pathname === "/" || urlObj.pathname === "/index.html")) {
      res.writeHead(200, {
        "Content-Type": "text/html; charset=utf-8",
        "Content-Security-Policy":
          "default-src 'self'; script-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; connect-src 'self'; img-src 'self' data:; frame-ancestors 'none'"
      });
      res.end(renderPortalHtml(activePort, csrfToken));
      return;
    }

    res.writeHead(404, { "Content-Type": "application/json; charset=utf-8" });
    res.end(JSON.stringify({ error: "Not found" }));
  });

  return new Promise((resolve, reject) => {
    server.on("error", (err) => reject(err));
    server.listen(port, "127.0.0.1", () => {
      const addr = server.address();
      const actualPort = typeof addr === "object" && addr ? addr.port : port;
      resolve({
        port: actualPort,
        url: `http://localhost:${actualPort}`,
        server
      });
    });
  });
}

function computeAggregateStats(events: JevSessionEvent[]) {
  let codexCount = 0;
  let geminiCount = 0;
  let cliCount = 0;
  let autopilotSavedCount = 0;
  let askHumanCount = 0;
  let totalLatency = 0;
  let totalCost = 0;
  const workspaces = new Set<string>();

  for (const e of events) {
    if (e.agent === "Codex") codexCount++;
    else if (e.agent === "Gemini") geminiCount++;
    else cliCount++;

    if (e.workspace) workspaces.add(e.workspace);

    if (e.verdict === "AUTOPILOT_PROCEED" || e.verdict === "ALLOW") {
      autopilotSavedCount++;
    } else if (e.verdict === "ASK_HUMAN" || e.verdict === "ASK_USER" || e.verdict === "BLOCK") {
      askHumanCount++;
    }

    totalLatency += e.latencyMs || 0;
    totalCost += e.costUsd || 0;
  }

  return {
    totalEvents: events.length,
    codexCount,
    geminiCount,
    cliCount,
    workspaceCount: workspaces.size,
    autopilotSavedCount,
    askHumanCount,
    avgLatencyMs: events.length > 0 ? Math.round(totalLatency / events.length) : 0,
    totalCostUsd: Number(totalCost.toFixed(5))
  };
}

function renderPortalHtml(_port: number, csrfToken: string): string {
  return `<!DOCTYPE html>
<html lang="vi">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>Jev Studio — Live Agent Q&A Monitor (SYSTEM-1 ONLINE)</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500;600;700&display=swap" rel="stylesheet">
  <script src="https://cdnjs.cloudflare.com/ajax/libs/gsap/3.12.5/gsap.min.js" defer></script>
  <style>
    :root {
      --bg-canvas: #f8fafc;
      --bg-white: #ffffff;
      --bg-subtle: #f1f5f9;
      --bg-hover: #f8fafc;

      --border-light: #e2e8f0;
      --border-med: #cbd5e1;

      --text-ink: #0f172a;
      --text-slate: #334155;
      --text-muted: #64748b;
      --text-faint: #94a3b8;

      --codex-green: #10b981;
      --codex-dark: #065f46;
      --codex-bg: #d1fae5;
      --codex-soft: #ecfdf5;
      --codex-border: #6ee7b7;

      --gemini-blue: #0284c7;
      --gemini-dark: #075985;
      --gemini-bg: #e0f2fe;
      --gemini-soft: #f0f9ff;
      --gemini-border: #7dd3fc;

      --amber-text: #92400e;
      --amber-bg: #fef3c7;
      --amber-border: #fcd34d;

      --rose-text: #9f1239;
      --rose-bg: #ffe4e6;
      --rose-border: #fda4af;

      --shadow-xs: 0 1px 2px rgba(15, 23, 42, 0.04);
      --shadow-sm: 0 2px 6px rgba(15, 23, 42, 0.05);
      --shadow-md: 0 8px 24px rgba(15, 23, 42, 0.08);
      --shadow-toast: 0 18px 38px rgba(15, 23, 42, 0.14);
    }

    * {
      box-sizing: border-box;
      margin: 0;
      padding: 0;
    }

    body {
      background-color: var(--bg-canvas);
      color: var(--text-ink);
      font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
      font-size: 13.5px;
      line-height: 1.5;
      height: 100vh;
      overflow: hidden;
      display: flex;
      -webkit-font-smoothing: antialiased;
    }

    .mono {
      font-family: 'JetBrains Mono', monospace;
      font-variant-numeric: tabular-nums;
    }

    /* Left White SaaS Sidebar (260px) */
    .sidebar {
      width: 260px;
      flex-shrink: 0;
      background: var(--bg-white);
      border-right: 1px solid var(--border-light);
      display: flex;
      flex-direction: column;
      justify-content: space-between;
      padding: 18px 14px;
      user-select: none;
    }

    .brand-header {
      display: flex;
      align-items: center;
      gap: 10px;
      padding: 2px 8px 18px;
      border-bottom: 1px solid var(--border-light);
      margin-bottom: 16px;
    }

    .brand-cube {
      width: 30px;
      height: 30px;
      border-radius: 8px;
      background: #0f172a;
      color: #ffffff;
      display: flex;
      align-items: center;
      justify-content: center;
      flex-shrink: 0;
      box-shadow: var(--shadow-xs);
    }

    .brand-title {
      font-size: 14.5px;
      font-weight: 700;
      letter-spacing: -0.02em;
      color: var(--text-ink);
    }

    .brand-subtitle {
      font-size: 11px;
      color: var(--text-muted);
      font-weight: 500;
    }

    .side-group-title {
      font-size: 11px;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: 0.06em;
      color: var(--text-muted);
      padding: 0 10px 8px;
    }

    .side-nav {
      display: flex;
      flex-direction: column;
      gap: 4px;
      margin-bottom: 22px;
    }

    .side-btn {
      appearance: none;
      border: 1px solid transparent;
      background: transparent;
      width: 100%;
      text-align: left;
      font-family: inherit;
      font-size: 13px;
      font-weight: 500;
      color: var(--text-slate);
      padding: 8px 10px;
      border-radius: 8px;
      cursor: pointer;
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 8px;
      transition: all 0.14s ease;
    }

    .side-btn:hover {
      background: var(--bg-subtle);
      color: var(--text-ink);
    }

    .side-btn.active {
      background: var(--bg-subtle);
      color: var(--text-ink);
      font-weight: 600;
      border-color: var(--border-light);
    }

    .side-btn-left {
      display: flex;
      align-items: center;
      gap: 9px;
      min-width: 0;
    }

    .agent-dot-ring {
      width: 14px;
      height: 14px;
      border-radius: 999px;
      display: inline-flex;
      align-items: center;
      justify-content: center;
      flex-shrink: 0;
    }

    .agent-dot-ring.codex {
      background: var(--codex-bg);
    }

    .agent-dot-ring.codex::after {
      content: "";
      width: 7px;
      height: 7px;
      border-radius: 999px;
      background: var(--codex-green);
    }

    .agent-dot-ring.gemini {
      background: var(--gemini-bg);
    }

    .agent-dot-ring.gemini::after {
      content: "";
      width: 7px;
      height: 7px;
      border-radius: 999px;
      background: var(--gemini-blue);
    }

    .ws-item {
      appearance: none;
      border: 1px solid transparent;
      background: transparent;
      width: 100%;
      text-align: left;
      font-family: inherit;
      padding: 8px 10px;
      border-radius: 8px;
      cursor: pointer;
      display: flex;
      align-items: flex-start;
      gap: 9px;
      transition: background-color 0.14s ease;
    }

    .ws-item:hover {
      background: var(--bg-subtle);
    }

    .ws-item.active {
      background: var(--codex-soft);
      border-color: var(--codex-border);
    }

    .ws-dot {
      width: 8px;
      height: 8px;
      border-radius: 999px;
      background: var(--codex-green);
      margin-top: 5px;
      flex-shrink: 0;
    }

    .ws-name {
      font-size: 13px;
      font-weight: 600;
      color: var(--text-ink);
      word-break: break-all;
    }

    .ws-sub {
      font-size: 11.5px;
      color: var(--text-muted);
    }

    .sidebar-bottom {
      border-top: 1px solid var(--border-light);
      padding-top: 12px;
      display: flex;
      flex-direction: column;
      gap: 6px;
    }

    /* Main Content Shell */
    .main-shell {
      flex: 1;
      min-width: 0;
      display: flex;
      flex-direction: column;
      height: 100vh;
      overflow: hidden;
    }

    /* Top SaaS Header Bar */
    .topbar {
      height: 62px;
      flex-shrink: 0;
      background: var(--bg-white);
      border-bottom: 1px solid var(--border-light);
      padding: 0 24px;
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 16px;
    }

    .crumb-bar {
      display: flex;
      align-items: center;
      gap: 8px;
      font-size: 14px;
    }

    .crumb-root {
      color: var(--text-muted);
      font-weight: 500;
    }

    .crumb-slash {
      color: var(--border-med);
    }

    .crumb-page {
      color: var(--text-ink);
      font-weight: 700;
    }

    .top-controls {
      display: flex;
      align-items: center;
      gap: 10px;
      flex-wrap: wrap;
    }

    .sse-pill {
      display: inline-flex;
      align-items: center;
      gap: 7px;
      padding: 5px 12px;
      border-radius: 999px;
      background: var(--codex-bg);
      color: var(--codex-dark);
      font-size: 12px;
      font-weight: 600;
    }

    .sse-dot {
      width: 7px;
      height: 7px;
      border-radius: 999px;
      background: var(--codex-green);
    }

    .search-field {
      position: relative;
      display: flex;
      align-items: center;
    }

    .search-field svg {
      position: absolute;
      left: 10px;
      width: 14px;
      height: 14px;
      color: var(--text-faint);
      pointer-events: none;
    }

    .search-input {
      background: var(--bg-canvas);
      border: 1px solid var(--border-light);
      border-radius: 8px;
      padding: 6px 12px 6px 31px;
      font-family: inherit;
      font-size: 12.5px;
      color: var(--text-ink);
      width: 210px;
      outline: none;
      transition: border-color 0.15s ease, background-color 0.15s ease;
    }

    .search-input:focus {
      background: var(--bg-white);
      border-color: var(--codex-green);
    }

    .btn-white {
      appearance: none;
      background: var(--bg-white);
      border: 1px solid var(--border-med);
      color: var(--text-ink);
      font-family: inherit;
      font-size: 12.5px;
      font-weight: 600;
      padding: 6px 13px;
      border-radius: 8px;
      cursor: pointer;
      display: inline-flex;
      align-items: center;
      gap: 6px;
      box-shadow: var(--shadow-xs);
      transition: all 0.14s ease;
    }

    .btn-white:hover {
      background: var(--bg-subtle);
    }

    .btn-emerald {
      appearance: none;
      background: var(--codex-green);
      border: 1px solid #059669;
      color: #ffffff;
      font-family: inherit;
      font-size: 12.5px;
      font-weight: 600;
      padding: 6px 13px;
      border-radius: 8px;
      cursor: pointer;
      display: inline-flex;
      align-items: center;
      gap: 6px;
      box-shadow: var(--shadow-xs);
      transition: all 0.14s ease;
    }

    .btn-emerald:hover {
      background: #059669;
    }

    /* Scrollable Workspace Content */
    .workspace-scroll {
      flex: 1;
      overflow-y: auto;
      padding: 20px 24px 36px;
      display: flex;
      flex-direction: column;
      gap: 18px;
    }

    /* 4 White KPI Cards */
    .kpi-grid {
      display: grid;
      grid-template-columns: repeat(4, 1fr);
      gap: 14px;
    }

    @media (max-width: 1080px) {
      .kpi-grid {
        grid-template-columns: repeat(2, 1fr);
      }
    }

    .kpi-card {
      background: var(--bg-white);
      border: 1px solid var(--border-light);
      border-radius: 12px;
      padding: 16px 18px;
      box-shadow: var(--shadow-xs);
      display: flex;
      flex-direction: column;
      justify-content: space-between;
      min-height: 112px;
    }

    .kpi-label {
      font-size: 12.5px;
      font-weight: 600;
      color: var(--text-slate);
    }

    .kpi-value {
      font-size: 29px;
      font-weight: 700;
      letter-spacing: -0.03em;
      color: var(--text-ink);
      margin: 4px 0;
    }

    .kpi-sub-green {
      font-size: 12px;
      font-weight: 600;
      color: var(--codex-green);
    }

    .kpi-sub-pill {
      display: inline-block;
      font-size: 11.5px;
      font-weight: 600;
      color: var(--text-slate);
      background: var(--bg-subtle);
      padding: 2px 9px;
      border-radius: 6px;
      width: fit-content;
    }

    .kpi-sub-muted {
      font-size: 12px;
      color: var(--text-muted);
    }

    /* Master-Detail Content Split */
    .split-layout {
      display: grid;
      grid-template-columns: 1.25fr 0.95fr;
      gap: 18px;
      align-items: start;
    }

    @media (max-width: 1140px) {
      .split-layout {
        grid-template-columns: 1fr;
      }
    }

    .panel-card {
      background: var(--bg-white);
      border: 1px solid var(--border-light);
      border-radius: 12px;
      box-shadow: var(--shadow-sm);
      padding: 18px 20px;
    }

    .panel-title {
      font-size: 15px;
      font-weight: 700;
      color: var(--text-ink);
      padding-bottom: 12px;
      border-bottom: 1px solid var(--border-light);
      display: flex;
      align-items: center;
      justify-content: space-between;
    }

    .list-col-headers {
      display: grid;
      grid-template-columns: 1fr 220px 72px;
      gap: 12px;
      padding: 10px 14px 8px;
      font-size: 11.5px;
      font-weight: 600;
      color: var(--text-muted);
    }

    .session-list {
      display: flex;
      flex-direction: column;
      gap: 10px;
    }

    .session-row-card {
      background: var(--bg-white);
      border: 1.5px solid var(--border-light);
      border-radius: 10px;
      padding: 14px 16px;
      display: grid;
      grid-template-columns: 1fr 220px 72px;
      gap: 14px;
      align-items: center;
      cursor: pointer;
      transition: all 0.14s ease;
    }

    .session-row-card:hover {
      border-color: var(--border-med);
      background: var(--bg-hover);
    }

    .session-row-card.selected {
      border-color: var(--codex-green);
      background: #f8fffb;
      box-shadow: 0 4px 14px rgba(16, 185, 129, 0.08);
    }

    @media (max-width: 720px) {
      .list-col-headers {
        display: none;
      }
      .session-row-card {
        grid-template-columns: 1fr;
      }
    }

    .row-badges {
      display: flex;
      align-items: center;
      gap: 8px;
      flex-wrap: wrap;
      margin-bottom: 8px;
    }

    .badge-agent {
      display: inline-flex;
      align-items: center;
      gap: 5px;
      padding: 3px 10px;
      border-radius: 6px;
      font-size: 12px;
      font-weight: 700;
    }

    .badge-agent.Codex {
      background: var(--codex-bg);
      color: var(--codex-dark);
    }

    .badge-agent.Gemini {
      background: var(--gemini-bg);
      color: var(--gemini-dark);
    }

    .badge-agent.CLI {
      background: var(--amber-bg);
      color: var(--amber-text);
    }

    .badge-project {
      display: inline-flex;
      align-items: center;
      gap: 5px;
      padding: 3px 10px;
      border-radius: 6px;
      background: var(--bg-subtle);
      border: 1px solid var(--border-light);
      color: var(--text-slate);
      font-size: 12px;
      font-weight: 600;
    }

    .row-question {
      font-size: 14.5px;
      font-weight: 600;
      color: var(--text-ink);
      line-height: 1.42;
    }

    .outcome-col {
      display: flex;
      flex-direction: column;
      gap: 5px;
    }

    .outcome-top {
      display: flex;
      align-items: center;
      justify-content: space-between;
      font-size: 12.5px;
      font-weight: 600;
      color: var(--text-ink);
    }

    .outcome-option-name {
      white-space: nowrap;
      overflow: hidden;
      text-overflow: ellipsis;
      max-width: 155px;
    }

    .bar-track {
      height: 6px;
      background: var(--bg-subtle);
      border-radius: 999px;
      overflow: hidden;
    }

    .bar-fill {
      height: 100%;
      width: 100%;
      border-radius: 999px;
      transform-origin: left center;
      transform: scaleX(0);
      will-change: transform;
    }

    .bar-fill.Codex {
      background: var(--codex-green);
    }

    .bar-fill.Gemini {
      background: var(--gemini-blue);
    }

    .bar-fill.CLI {
      background: #f59e0b;
    }

    .verdict-chip {
      display: inline-flex;
      align-items: center;
      padding: 2px 9px;
      border-radius: 6px;
      font-size: 11px;
      font-weight: 700;
      width: fit-content;
      margin-top: 2px;
    }

    .verdict-chip.AUTOPILOT_PROCEED,
    .verdict-chip.ALLOW {
      background: var(--codex-bg);
      color: var(--codex-dark);
    }

    .verdict-chip.ASK_HUMAN,
    .verdict-chip.ASK_USER {
      background: var(--amber-bg);
      color: var(--amber-text);
    }

    .verdict-chip.BLOCK {
      background: var(--rose-bg);
      color: var(--rose-text);
    }

    .verdict-chip.INFO {
      background: var(--gemini-bg);
      color: var(--gemini-dark);
    }

    .latency-col {
      text-align: right;
      font-size: 12.5px;
      font-weight: 600;
      color: var(--text-slate);
    }

    /* Right Inspector Panel */
    .inspector-sticky {
      position: sticky;
      top: 0;
    }

    .insp-block {
      margin-top: 16px;
    }

    .insp-step-label {
      font-size: 11px;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: 0.05em;
      color: var(--text-slate);
      margin-bottom: 8px;
    }

    .path-banner {
      background: var(--bg-subtle);
      border: 1px solid var(--border-light);
      border-radius: 8px;
      padding: 10px 12px;
      font-size: 12px;
      color: var(--text-slate);
      word-break: break-all;
      line-height: 1.45;
    }

    .insp-question-box {
      background: var(--bg-canvas);
      border: 1px solid var(--border-light);
      border-left: 3.5px solid var(--codex-green);
      border-radius: 8px;
      padding: 12px 14px;
      font-size: 13.5px;
      font-weight: 600;
      color: var(--text-ink);
      margin-bottom: 10px;
    }

    .cand-list {
      display: flex;
      flex-direction: column;
      gap: 9px;
    }

    .cand-item {
      background: var(--bg-white);
      border: 1.5px solid var(--border-light);
      border-radius: 9px;
      padding: 11px 13px;
    }

    .cand-item.winner {
      background: var(--codex-soft);
      border-color: var(--codex-green);
    }

    .cand-row-top {
      display: flex;
      align-items: flex-start;
      justify-content: space-between;
      gap: 10px;
      margin-bottom: 6px;
    }

    .cand-left {
      display: flex;
      align-items: flex-start;
      gap: 8px;
      font-size: 12.5px;
      font-weight: 600;
      color: var(--text-ink);
      line-height: 1.4;
    }

    .check-circle {
      width: 18px;
      height: 18px;
      border-radius: 999px;
      background: var(--codex-green);
      color: #ffffff;
      display: inline-flex;
      align-items: center;
      justify-content: center;
      flex-shrink: 0;
      margin-top: 1px;
    }

    .empty-circle {
      width: 18px;
      height: 18px;
      border-radius: 999px;
      border: 1.5px solid var(--border-med);
      flex-shrink: 0;
      margin-top: 1px;
    }

    .directive-alert {
      border-radius: 8px;
      padding: 11px 13px;
      font-size: 12.5px;
      font-weight: 600;
      display: flex;
      align-items: flex-start;
      gap: 9px;
      margin-bottom: 10px;
      line-height: 1.45;
    }

    .directive-alert.proceed {
      background: var(--codex-green);
      color: #ffffff;
    }

    .directive-alert.ask {
      background: #f59e0b;
      color: #ffffff;
    }

    .directive-code {
      background: var(--bg-subtle);
      border: 1px solid var(--border-light);
      border-radius: 8px;
      padding: 11px 13px;
      font-size: 11.5px;
      color: var(--text-slate);
      line-height: 1.5;
      white-space: pre-wrap;
      word-break: break-word;
    }

    /* Bottom-Right Crisp White Floating Toast */
    .toast-stack {
      position: fixed;
      bottom: 22px;
      right: 22px;
      z-index: 9999;
      display: flex;
      flex-direction: column;
      gap: 10px;
      pointer-events: none;
    }

    .white-toast {
      pointer-events: auto;
      background: var(--bg-white);
      border: 1px solid var(--border-light);
      border-left: 4px solid var(--codex-green);
      border-radius: 10px;
      padding: 13px 16px;
      box-shadow: var(--shadow-toast);
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 12px;
      min-width: 340px;
      max-width: 440px;
      will-change: transform, opacity;
    }

    .white-toast[data-agent="Gemini"] {
      border-left-color: var(--gemini-blue);
    }

    .toast-text {
      font-size: 13px;
      font-weight: 600;
      color: var(--text-ink);
      line-height: 1.4;
    }

    .toast-close-btn {
      background: transparent;
      border: none;
      color: var(--text-faint);
      font-size: 18px;
      cursor: pointer;
      line-height: 1;
    }

    /* Feedback Calibration Bar inside Inspector */
    .feedback-box {
      margin-top: 12px;
      background: var(--bg-canvas);
      border: 1px solid var(--border-light);
      border-radius: 9px;
      padding: 11px 13px;
    }

    .feedback-actions {
      display: flex;
      align-items: center;
      gap: 8px;
      flex-wrap: wrap;
      margin-top: 7px;
    }

    .btn-fb-good,
    .btn-fb-bad {
      appearance: none;
      font-family: inherit;
      font-size: 12px;
      font-weight: 600;
      padding: 6px 11px;
      border-radius: 7px;
      cursor: pointer;
      transition: all 0.14s ease;
    }

    .btn-fb-good {
      background: var(--codex-soft);
      border: 1px solid var(--codex-border);
      color: var(--codex-dark);
    }

    .btn-fb-good:hover {
      background: var(--codex-bg);
    }

    .btn-fb-bad {
      background: var(--rose-bg);
      border: 1px solid var(--rose-border);
      color: var(--rose-text);
    }

    .btn-fb-bad:hover {
      background: #fecdd3;
    }

    /* Project Brain Modal Overlay */
    .modal-overlay {
      position: fixed;
      inset: 0;
      background: rgba(15, 23, 42, 0.45);
      backdrop-filter: blur(3px);
      z-index: 9000;
      display: none;
      align-items: center;
      justify-content: center;
      padding: 24px;
    }

    .modal-overlay.open {
      display: flex;
    }

    .brain-modal {
      background: var(--bg-white);
      border: 1px solid var(--border-light);
      border-radius: 14px;
      box-shadow: var(--shadow-toast);
      width: 100%;
      max-width: 960px;
      max-height: 86vh;
      display: flex;
      flex-direction: column;
      overflow: hidden;
    }

    .brain-modal-header {
      padding: 16px 22px;
      border-bottom: 1px solid var(--border-light);
      display: flex;
      align-items: center;
      justify-content: space-between;
    }

    .brain-modal-body {
      padding: 18px 22px;
      overflow-y: auto;
      display: flex;
      flex-direction: column;
      gap: 14px;
    }

    .brain-project-card {
      border: 1px solid var(--border-light);
      border-radius: 10px;
      padding: 14px 16px;
      background: var(--bg-canvas);
    }

    .lang-switch {
      display: inline-flex;
      align-items: center;
      background: var(--bg-subtle);
      border: 1px solid var(--border-light);
      border-radius: 8px;
      padding: 2px;
      gap: 2px;
    }

    .lang-btn {
      border: none;
      background: transparent;
      color: var(--text-muted);
      font-size: 11.5px;
      font-weight: 700;
      padding: 4px 8px;
      border-radius: 6px;
      cursor: pointer;
      transition: background 0.15s ease, color 0.15s ease;
    }

    .lang-btn.active {
      background: var(--bg-white);
      color: var(--text-ink);
      box-shadow: var(--shadow-xs);
    }
  </style>
</head>
<body>
  <!-- Left White SaaS Sidebar -->
  <aside class="sidebar">
    <div>
      <div class="brand-header">
        <div class="brand-cube">
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2">
            <path d="M21 16V8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16z"></path>
            <polyline points="3.27 6.96 12 12.01 20.73 6.96"></polyline>
            <line x1="12" y1="22.08" x2="12" y2="12"></line>
          </svg>
        </div>
        <div>
          <div class="brand-title">Jev Studio</div>
          <div class="brand-subtitle">Agent Monitor · SYSTEM-1 ONLINE</div>
        </div>
      </div>

      <div class="side-group-title" id="lblFilterAgent">Filter by Agent</div>
      <nav class="side-nav" id="agentNav">
        <button class="side-btn active" data-agent-filter="ALL" type="button">
          <span class="side-btn-left">
            <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
              <path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"></path>
              <circle cx="9" cy="7" r="4"></circle>
              <path d="M23 21v-2a4 4 0 0 0-3-3.87"></path>
              <path d="M16 3.13a4 4 0 0 1 0 7.75"></path>
            </svg>
            <span><span id="lblAllAgents">All Agents</span> (<span id="sideCountAll">0</span>)</span>
          </span>
        </button>

        <button class="side-btn" data-agent-filter="Codex" type="button">
          <span class="side-btn-left">
            <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="#059669" stroke-width="2">
              <circle cx="12" cy="12" r="9"></circle>
              <circle cx="12" cy="12" r="3"></circle>
            </svg>
            <span>OpenAI Codex (<span id="sideCountCodex">0</span>)</span>
          </span>
          <span class="agent-dot-ring codex"></span>
        </button>

        <button class="side-btn" data-agent-filter="Gemini" type="button">
          <span class="side-btn-left">
            <svg width="15" height="15" viewBox="0 0 24 24" fill="#0284c7">
              <path d="M12 2C12.8 7.2 16.8 11.2 22 12C16.8 12.8 12.8 16.8 12 22C11.2 16.8 7.2 12.8 2 12C7.2 11.2 11.2 7.2 12 2Z"/>
            </svg>
            <span>Gemini / Antigravity (<span id="sideCountGemini">0</span>)</span>
          </span>
          <span class="agent-dot-ring gemini"></span>
        </button>
      </nav>

      <div class="side-group-title" id="lblActiveWorkspaces">Active Workspaces</div>
      <div class="side-nav" id="workspaceNav"></div>
    </div>

    <div class="sidebar-bottom">
      <button class="side-btn" id="btnNotify" type="button">
        <span class="side-btn-left">
          <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <path d="M18 8A6 6 0 0 0 6 8c0 7-3 9-3 9h18s-3-2-3-9"></path>
            <path d="M13.73 21a2 2 0 0 1-3.46 0"></path>
          </svg>
          <span id="notifyLabel">Enable Desktop Alerts</span>
        </span>
      </button>

      <button class="side-btn" id="btnClear" type="button">
        <span class="side-btn-left">
          <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <polyline points="3 6 5 6 21 6"></polyline>
            <path d="M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6"></path>
          </svg>
          <span id="lblClearHistory">Clear Session Log</span>
        </span>
      </button>
    </div>
  </aside>

  <!-- Main Content Shell -->
  <div class="main-shell">
    <header class="topbar">
      <div class="crumb-bar">
        <span class="crumb-root">MCP-Jev</span>
        <span class="crumb-slash">/</span>
        <span class="crumb-page">Live Agent Q&amp;A &amp; Guardrail Monitor</span>
      </div>

      <div class="top-controls">
        <div class="sse-pill">
          <span class="sse-dot"></span>
          <span id="sseStatusText">Live SSE Connected</span>
        </div>

        <div class="search-field">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <circle cx="11" cy="11" r="8"></circle>
            <line x1="21" y1="21" x2="16.65" y2="16.65"></line>
          </svg>
          <input type="text" id="searchInput" class="search-input" placeholder="Search commands, specs, workspaces..." />
        </div>

        <button class="btn-white" id="btnOpenBrain" type="button">🧠 Project Brain</button>
        <button class="btn-white" id="btnSimCodex" type="button">+ Test Codex</button>
        <button class="btn-emerald" id="btnSimGemini" type="button">+ Test Gemini</button>
        <div class="lang-switch" role="group" aria-label="Language switcher">
          <button class="lang-btn" id="btnLangEn" data-lang="en" type="button">EN</button>
          <button class="lang-btn" id="btnLangVi" data-lang="vi" type="button">VI</button>
        </div>
      </div>
    </header>

    <div class="workspace-scroll">
      <!-- 4 White KPI Cards -->
      <section class="kpi-grid">
        <div class="kpi-card">
          <div class="kpi-label" id="lblKpiTotal">Total Evaluated Events</div>
          <div class="kpi-value mono" id="kpiTotal">0</div>
          <div class="kpi-sub-green" id="lblKpiRealtime">● Real-time SSE stream</div>
        </div>

        <div class="kpi-card">
          <div class="kpi-label" id="lblKpiProjects">Active Workspaces &amp; Agents</div>
          <div class="kpi-value" id="kpiProjects">0 Workspaces</div>
          <div class="kpi-sub-pill mono" id="kpiAgentSplit">Codex 50% · Gemini 50%</div>
        </div>

        <div class="kpi-card">
          <div class="kpi-label" id="lblKpiPassRate">Clean Allow / Autopilot Rate</div>
          <div class="kpi-value mono" id="kpiAutopilotRate">100%</div>
          <div class="kpi-sub-green" id="kpiSavedText">Passed without escalation</div>
        </div>

        <div class="kpi-card">
          <div class="kpi-label" id="lblKpiLatency">Average System-1 Latency</div>
          <div class="kpi-value mono" id="kpiLatency">0 ms</div>
          <div class="kpi-sub-muted mono" id="kpiCost">Cost $0.0000</div>
        </div>
      </section>

      <!-- Master-Detail Split -->
      <section class="split-layout">
        <!-- Left: Live Sessions List -->
        <div class="panel-card">
          <div class="panel-title">
            <span id="lblSessionListTitle">Live Agent Guardrail &amp; Decision Feed</span>
            <span class="mono" style="font-size:11.5px; color:var(--text-muted);" id="activeFilterLabel">All Workspaces</span>
          </div>

          <div class="list-col-headers">
            <span id="lblColQuestion">Agent &amp; Workspace / Evaluated Prompt</span>
            <span id="lblColOutcome">Calibrated Verdict &amp; Probability</span>
            <span style="text-align:right;" id="lblColLatency">Latency</span>
          </div>

          <div class="session-list" id="sessionList"></div>
        </div>

        <!-- Right: Detailed Session Inspector -->
        <aside class="panel-card inspector-sticky" id="inspectorPanel">
          <div class="panel-title">
            <span id="lblInspectorTitle">Decision Inspector — Jev Verdict</span>
            <span class="mono" style="font-size:11.5px; color:var(--text-muted);" id="inspTime">—</span>
          </div>
          <div id="inspectorBody"></div>
        </aside>
      </section>
    </div>
  </div>

  <!-- Floating White Toast Container -->
  <div class="toast-stack" id="toastViewport"></div>

  <!-- Project Brain Modal -->
  <div class="modal-overlay" id="brainModalOverlay">
    <div class="brain-modal">
      <div class="brain-modal-header">
        <div>
          <div style="font-size:16px; font-weight:700; color:var(--text-ink);" id="lblBrainModalTitle">🧠 Persistent Project Brain</div>
          <div style="font-size:12px; color:var(--text-muted);" id="lblBrainModalSub">Workspace DNA, tech stack topology, and learned human override rules (~/.mcp-jev/projects/*.json)</div>
        </div>
        <button class="btn-white" id="btnCloseBrain" type="button">Close (ESC)</button>
      </div>
      <div class="brain-modal-body" id="brainModalBody">
        <div style="padding:24px; text-align:center; color:var(--text-muted);">Loading project profiles...</div>
      </div>
    </div>
  </div>

  <script>
    const JEV_CSRF_TOKEN = "${csrfToken}";
    let currentLang = (function() {
      try {
        const saved = localStorage.getItem("jev_lang");
        if (saved === "en" || saved === "vi") return saved;
      } catch {}
      return ((navigator.language || "").toLowerCase().startsWith("vi")) ? "vi" : "en";
    })();

    const I18N = {
      en: {
        filterAgent: "Filter by Agent",
        allAgents: "All Agents",
        activeWorkspaces: "Active Workspaces",
        enableNotify: "Enable Desktop Alerts",
        enabledNotify: "Desktop Alerts Enabled",
        clearHistory: "Clear Session Log",
        sseConnected: "Live SSE Connected",
        sseReconnecting: "Reconnecting SSE...",
        searchPlaceholder: "Search commands, specs, workspaces...",
        projectBrainBtn: "🧠 Project Brain",
        kpiTotal: "Total Evaluated Events",
        kpiRealtime: "● Real-time SSE stream",
        kpiProjects: "Active Workspaces & Agents",
        workspacesUnit: "Workspaces",
        kpiPassRate: "Clean Allow / Autopilot Rate",
        savedCount: (n) => \`Auto-approved / clean (\${n} events)\`,
        kpiLatency: "Average System-1 Latency",
        costPrefix: "Cost",
        sessionListTitle: "Live Agent Guardrail & Decision Feed",
        colQuestion: "Agent & Workspace / Evaluated Prompt",
        colOutcome: "Calibrated Verdict & Probability",
        colLatency: "Latency",
        inspectorTitle: "Decision Inspector — Jev Verdict",
        brainModalTitle: "🧠 Persistent Project Brain",
        brainModalSub: "Workspace DNA, tech stack topology, and learned human override rules (~/.mcp-jev/projects/*.json)",
        closeEsc: "Close (ESC)",
        noWorkspaceCalls: "No workspace events yet",
        allWorkspaces: "All Workspaces",
        showAllWorkspaces: "Showing all repositories",
        sessionsUnit: "events",
        emptyList: "No matching events yet. Click <strong>+ Test Codex</strong> or <strong>+ Test Gemini</strong> in the top bar to try a live check!",
        emptyInspector: "Select an event on the left to inspect probabilities and directives.",
        verdictAutopilot: "Autopilot Proceed",
        verdictAskHuman: "Ask Human",
        verdictAllow: "Allow",
        verdictBlock: "Block",
        optionPrefix: "Option",
        step1: "[1] CALLING AGENT & TARGET WORKSPACE",
        projectLabel: "Workspace",
        projectPathLabel: "Workspace Path",
        step2Choice: "[2] QUESTION & CANDIDATE OPTIONS",
        step2Metrics: "[2] EVALUATED PAYLOAD & CALIBRATED PROBABILITIES",
        step3: "[3] POLICY VERDICT & AGENT DIRECTIVE",
        bannerProceed: (agent, opt) => \`Jev directive to \${agent}: Proceed with "\${opt}".\`,
        bannerAsk: (agent, opt) => \`Jev directive to \${agent}: Escalate to human confirmation (top score: "\${opt}").\`,
        fbTitle: "🎯 Calibrate & Teach Project Brain for",
        fbSub: (ws) => \`Saved permanently to <span class="mono">~/.mcp-jev/projects/\${ws}.json</span> and injected into future evaluations.\`,
        fbGoodBtn: "👍 Verdict is accurate",
        fbBadBtn: "👎 Override / Teach rule",
        fbSavedGood: (ws) => \`✓ Confirmed accurate pattern in Project Brain (\${ws})!\`,
        fbPrompt: (ws) => \`Enter a persistent project rule or override for \${ws}:\`,
        fbSavedRule: (ws) => \`✓ Saved override rule into Project Brain (\${ws})!\`,
        toastAsked: (ws) => \`[Workspace: <strong>\${ws}</strong>] evaluated via Jev\`,
        toastVerdictPrefix: "➔ Verdict",
        loadingBrain: "Reading Project Brain profiles from ~/.mcp-jev/projects/...",
        emptyBrain: "No Project Brain profiles saved yet.",
        deleteBtn: "Delete",
        noCustomRules: "No manual human override rules recorded yet.",
        addRuleBtn: "+ Add Custom Rule",
        topologyLabel: "Directory Topology",
        domainAuthLabel: "Domain / Auth Fingerprint",
        learnedRulesHeader: (n) => \`Learned Human Override Rules (\${n})\`,
        addRulePrompt: (ws) => \`Enter a custom rule or invariant for workspace \${ws}:\`,
        metrics: {
          spec_fulfilled: "Spec Alignment (P(fulfills_spec))",
          quality_norm: "Code Quality Score",
          regression_risk: "Bug / Regression Risk",
          security_risk: "Security Risk",
          safe_probability: "Execution Safety (P(safe))",
          destructive_risk: "Destructive / Irreversible Risk",
          secret_exfiltration: "Secret / Network Exfiltration Risk",
          blast_radius_norm: "Blast Radius",
          security_score_norm: "Overall Security Score"
        }
      },
      vi: {
        filterAgent: "Lọc Theo Agent",
        allAgents: "Tất cả Agent",
        activeWorkspaces: "Dự Án Đang Chạy",
        enableNotify: "Bật Popup Thông Báo",
        enabledNotify: "Đã Bật Popup Thông Báo",
        clearHistory: "Xoá Lịch Sử Phiên",
        sseConnected: "Đang kết nối trực tiếp (Live SSE)",
        sseReconnecting: "Đang kết nối lại SSE...",
        searchPlaceholder: "Tìm câu lệnh, spec, dự án...",
        projectBrainBtn: "🧠 Bộ Não Dự Án",
        kpiTotal: "Tổng Phiên Đánh Giá",
        kpiRealtime: "● Tự động cập nhật thời gian thực",
        kpiProjects: "Dự Án & Agent Đang Chạy",
        workspacesUnit: "Dự án",
        kpiPassRate: "Tỷ Lệ An Toàn / Tự Quyết",
        savedCount: (n) => \`Đạt chuẩn / tự duyệt (\${n} lần)\`,
        kpiLatency: "Độ Trễ Trung Bình",
        costPrefix: "Chi phí",
        sessionListTitle: "Danh Sách Phiên Hỏi Đáp & Kiểm Duyệt Trực Tiếp",
        colQuestion: "Agent & Dự án / Nội dung kiểm tra",
        colOutcome: "Phán quyết & Xác suất Jev",
        colLatency: "Độ trễ",
        inspectorTitle: "Chi Tiết Phiên — Phán Quyết Jev",
        brainModalTitle: "🧠 Bộ Não Dự Án (Persistent Project Brain)",
        brainModalSub: "Hồ sơ kiến trúc, tech stack, cấu trúc thư mục và quy tắc hiệu chỉnh Jev đã học (~/.mcp-jev/projects/*.json)",
        closeEsc: "Đóng (ESC)",
        noWorkspaceCalls: "Chưa có dự án nào gọi",
        allWorkspaces: "Tất cả dự án",
        showAllWorkspaces: "Hiển thị toàn bộ workspace",
        sessionsUnit: "phiên",
        emptyList: "Chưa có phiên nào khớp bộ lọc. Bấm nút <strong>+ Test Codex</strong> hoặc <strong>+ Test Gemini</strong> ở góc trên để thử ngay!",
        emptyInspector: "Chọn một phiên bên trái để xem chi tiết xác suất và chỉ thị.",
        verdictAutopilot: "Tự quyết (Autopilot)",
        verdictAskHuman: "Hỏi người dùng (Ask Human)",
        verdictAllow: "Cho phép (Allow)",
        verdictBlock: "Chặn (Block)",
        optionPrefix: "Phương án",
        step1: "[1] AGENT & DỰ ÁN ĐANG SỬ DỤNG",
        projectLabel: "Dự án",
        projectPathLabel: "Đường dẫn dự án",
        step2Choice: "[2] CÂU HỎI & CÁC PHƯƠNG ÁN AGENT ĐƯA RA",
        step2Metrics: "[2] NỘI DUNG KIỂM TRA & BẢNG CHẤM ĐIỂM CỦA JEV",
        step3: "[3] KẾT QUẢ & CHỈ THỊ JEV TRẢ VỀ",
        bannerProceed: (agent, opt) => \`Jev chỉ thị cho \${agent}: Thực thi phương án "\${opt}".\`,
        bannerAsk: (agent, opt) => \`Jev chỉ thị cho \${agent}: Dừng lại hỏi xác nhận người dùng (gợi ý đầu: "\${opt}").\`,
        fbTitle: "🎯 Hiệu chỉnh & Dạy lại Jev cho dự án",
        fbSub: (ws) => \`Phản hồi được lưu vĩnh viễn vào <span class="mono">~/.mcp-jev/projects/\${ws}.json</span> và bơm thẳng vào các lần gọi sau.\`,
        fbGoodBtn: "👍 Phán quyết chuẩn",
        fbBadBtn: "👎 Jev xử sai — Dạy lại quy tắc",
        fbSavedGood: (ws) => \`✓ Đã ghi nhận mẫu chuẩn vào Bộ Não Dự Án (\${ws})!\`,
        fbPrompt: (ws) => \`Nhập quy tắc dạy lại Jev cho dự án \${ws}:\`,
        fbSavedRule: (ws) => \`✓ Đã nạp quy tắc hiệu chỉnh mới vào Bộ Não Dự Án (\${ws})!\`,
        toastAsked: (ws) => \`[Dự án: <strong>\${ws}</strong>] vừa gọi Jev\`,
        toastVerdictPrefix: "➔ Chốt",
        loadingBrain: "Đang đọc Bộ Não Dự Án từ ~/.mcp-jev/projects/...",
        emptyBrain: "Chưa có hồ sơ dự án nào được lưu.",
        deleteBtn: "Xoá",
        noCustomRules: "Chưa có quy tắc hiệu chỉnh thủ công nào.",
        addRuleBtn: "+ Thêm quy tắc riêng",
        topologyLabel: "Cấu trúc thư mục",
        domainAuthLabel: "Đặc trưng Domain/Auth",
        learnedRulesHeader: (n) => \`Quy tắc hiệu chỉnh Jev đã học (\${n})\`,
        addRulePrompt: (ws) => \`Nhập quy tắc bắt buộc hoặc lưu ý đặc thù cho dự án \${ws}:\`,
        metrics: {
          spec_fulfilled: "Độ khớp yêu cầu (Spec Fulfilled)",
          quality_norm: "Chất lượng Code (Code Quality)",
          regression_risk: "Rủi ro gây lỗi (Regression Risk)",
          security_risk: "Rủi ro bảo mật (Security Risk)",
          safe_probability: "Xác suất an toàn (Safe Probability)",
          destructive_risk: "Rủi ro phá huỷ (Destructive Risk)",
          secret_exfiltration: "Rủi ro lộ Secret (Secret Risk)",
          blast_radius_norm: "Phạm vi ảnh hưởng (Blast Radius)",
          security_score_norm: "Điểm an toàn bảo mật (Security Score)"
        }
      }
    };

    function t() {
      return I18N[currentLang] || I18N.en;
    }

    let allEvents = [];
    let selectedAgentFilter = "ALL";
    let selectedWorkspaceFilter = "ALL";
    let searchQuery = "";
    let selectedEventId = null;
    let desktopNotifyEnabled = false;

    function escapeHtml(str) {
      return String(str ?? "")
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#39;");
    }

    function formatAgentBadgeText(agent) {
      if (agent === "Codex") return "OpenAI Codex";
      if (agent === "Claude") return "Claude Code";
      if (agent === "Cursor") return "Cursor";
      if (agent === "Gemini") return "Gemini";
      return "CLI";
    }

    function formatVerdictChipText(verdict) {
      if (verdict === "AUTOPILOT_PROCEED") return t().verdictAutopilot;
      if (verdict === "ASK_HUMAN" || verdict === "ASK_USER") return t().verdictAskHuman;
      if (verdict === "ALLOW") return t().verdictAllow;
      if (verdict === "BLOCK") return t().verdictBlock;
      return verdict;
    }

    function formatTime(iso) {
      try {
        const d = new Date(iso);
        const loc = currentLang === "vi" ? "vi-VN" : "en-US";
        return d.toLocaleTimeString(loc, { hour12: false }) + " · " + d.toLocaleDateString(loc);
      } catch {
        return iso;
      }
    }

    function applyStaticTranslations() {
      const tr = t();
      document.documentElement.lang = currentLang;
      document.getElementById("btnLangEn")?.classList.toggle("active", currentLang === "en");
      document.getElementById("btnLangVi")?.classList.toggle("active", currentLang === "vi");

      document.getElementById("lblFilterAgent").textContent = tr.filterAgent;
      document.getElementById("lblAllAgents").textContent = tr.allAgents;
      document.getElementById("lblActiveWorkspaces").textContent = tr.activeWorkspaces;
      document.getElementById("notifyLabel").textContent = desktopNotifyEnabled ? tr.enabledNotify : tr.enableNotify;
      document.getElementById("lblClearHistory").textContent = tr.clearHistory;
      document.getElementById("searchInput").placeholder = tr.searchPlaceholder;
      document.getElementById("btnOpenBrain").textContent = tr.projectBrainBtn;
      document.getElementById("lblKpiTotal").textContent = tr.kpiTotal;
      document.getElementById("lblKpiRealtime").textContent = tr.kpiRealtime;
      document.getElementById("lblKpiProjects").textContent = tr.kpiProjects;
      document.getElementById("lblKpiPassRate").textContent = tr.kpiPassRate;
      document.getElementById("lblKpiLatency").textContent = tr.kpiLatency;
      document.getElementById("lblSessionListTitle").textContent = tr.sessionListTitle;
      document.getElementById("lblColQuestion").textContent = tr.colQuestion;
      document.getElementById("lblColOutcome").textContent = tr.colOutcome;
      document.getElementById("lblColLatency").textContent = tr.colLatency;
      document.getElementById("lblInspectorTitle").textContent = tr.inspectorTitle;
      document.getElementById("lblBrainModalTitle").textContent = tr.brainModalTitle;
      document.getElementById("lblBrainModalSub").textContent = tr.brainModalSub;
      document.getElementById("btnCloseBrain").textContent = tr.closeEsc;
    }

    function computeLocalStats(events) {
      let codexCount = 0, geminiCount = 0, cliCount = 0, autopilotSavedCount = 0, totalLatency = 0, totalCost = 0;
      const workspaces = new Set();
      for (const e of events) {
        if (e.agent === "Codex") codexCount++;
        else if (e.agent === "Gemini") geminiCount++;
        else cliCount++;
        if (e.workspace) workspaces.add(e.workspace);
        if (e.verdict === "AUTOPILOT_PROCEED" || e.verdict === "ALLOW") autopilotSavedCount++;
        totalLatency += (e.latencyMs || 0);
        totalCost += (e.costUsd || 0);
      }
      return {
        totalEvents: events.length,
        codexCount,
        geminiCount,
        cliCount,
        workspaceCount: workspaces.size,
        autopilotSavedCount,
        avgLatencyMs: events.length ? Math.round(totalLatency / events.length) : 0,
        totalCostUsd: totalCost
      };
    }

    function renderWorkspaceSidebar() {
      const wsMap = new Map();
      for (const e of allEvents) {
        const ws = e.workspace || "workspace";
        if (!wsMap.has(ws)) {
          wsMap.set(ws, { agents: new Set(), count: 0 });
        }
        const entry = wsMap.get(ws);
        entry.agents.add(e.agent);
        entry.count++;
      }

      const container = document.getElementById("workspaceNav");
      if (wsMap.size === 0) {
        container.innerHTML = \`<div style="padding:6px 10px; font-size:12px; color:var(--text-muted);">\${escapeHtml(t().noWorkspaceCalls)}</div>\`;
        return;
      }

      let html = \`
        <button class="ws-item \${selectedWorkspaceFilter === 'ALL' ? 'active' : ''}" data-ws="ALL" type="button">
          <span class="ws-dot"></span>
          <div>
            <div class="ws-name">\${escapeHtml(t().allWorkspaces)} (\${wsMap.size})</div>
            <div class="ws-sub">\${escapeHtml(t().showAllWorkspaces)}</div>
          </div>
        </button>
      \`;

      for (const [wsName, info] of wsMap.entries()) {
        const agentList = Array.from(info.agents).join(", ");
        const isActive = selectedWorkspaceFilter === wsName;
        html += \`
          <button class="ws-item \${isActive ? 'active' : ''}" data-ws="\${escapeHtml(wsName)}" type="button">
            <span class="ws-dot"></span>
            <div>
              <div class="ws-name">\${escapeHtml(wsName)}</div>
              <div class="ws-sub">\${escapeHtml(agentList)} active · \${info.count} \${escapeHtml(t().sessionsUnit)}</div>
            </div>
          </button>
        \`;
      }
      container.innerHTML = html;
    }

    function updateKpis(stats) {
      document.getElementById("kpiTotal").textContent = stats.totalEvents;
      document.getElementById("sideCountAll").textContent = stats.totalEvents;
      document.getElementById("sideCountCodex").textContent = stats.codexCount;
      document.getElementById("sideCountGemini").textContent = stats.geminiCount;

      document.getElementById("kpiProjects").textContent = (stats.workspaceCount || 0) + " " + t().workspacesUnit;

      const pairTotal = stats.codexCount + stats.geminiCount;
      const cPct = pairTotal === 0 ? 50 : Math.round((stats.codexCount / pairTotal) * 100);
      const gPct = pairTotal === 0 ? 50 : 100 - cPct;
      document.getElementById("kpiAgentSplit").textContent = \`Codex \${cPct}% · Gemini \${gPct}%\`;

      const rate = stats.totalEvents > 0
        ? ((stats.autopilotSavedCount / stats.totalEvents) * 100).toFixed(1) + "%"
        : "100%";
      document.getElementById("kpiAutopilotRate").textContent = rate;
      document.getElementById("kpiSavedText").textContent = t().savedCount(stats.autopilotSavedCount);

      document.getElementById("kpiLatency").textContent = stats.avgLatencyMs + " ms";
      document.getElementById("kpiCost").textContent = \`\${t().costPrefix} $\${stats.totalCostUsd.toFixed(4)}\`;

      renderWorkspaceSidebar();
    }

    function getFilteredEvents() {
      return allEvents.filter((e) => {
        if (selectedAgentFilter !== "ALL" && e.agent !== selectedAgentFilter) return false;
        if (selectedWorkspaceFilter !== "ALL" && e.workspace !== selectedWorkspaceFilter) return false;
        if (searchQuery) {
          const hay = (e.questionOrTitle + " " + e.workspace + " " + (e.workspacePath || "") + " " + e.tool + " " + e.selectedOption + " " + e.directive).toLowerCase();
          if (!hay.includes(searchQuery)) return false;
        }
        return true;
      });
    }

    function renderInspector(evt) {
      const timeEl = document.getElementById("inspTime");
      const bodyEl = document.getElementById("inspectorBody");

      if (!evt) {
        timeEl.textContent = "—";
        bodyEl.innerHTML = \`<div style="padding:32px 0; text-align:center; color:var(--text-muted);">\${escapeHtml(t().emptyInspector)}</div>\`;
        return;
      }

      timeEl.textContent = formatTime(evt.timestamp);
      const optEntries = Object.entries(evt.optionsOrInput || {});
      const probs = evt.probabilities || {};
      const isChoiceTool = evt.tool === "jev_autopilot_decide" || evt.tool === "jev_route_task";

      let section2Html = "";
      if (isChoiceTool) {
        const candidatesHtml = optEntries.map(([key, desc], idx) => {
          const isWinner = key === evt.selectedOption || evt.selectedOption.startsWith(key);
          const rawProb = probs[key] !== undefined
            ? Number(probs[key])
            : isWinner
            ? Number(evt.selectedProbability || 0.9)
            : 0;
          const pct = Math.round(rawProb * 100);
          const letter = String.fromCharCode(65 + idx);

          return \`
            <div class="cand-item \${isWinner ? 'winner' : ''}">
              <div class="cand-row-top">
                <div class="cand-left">
                  \${isWinner
                    ? \`<span class="check-circle"><svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3"><polyline points="20 6 9 17 4 12"></polyline></svg></span>\`
                    : \`<span class="empty-circle"></span>\`
                  }
                  <span>\${escapeHtml(t().optionPrefix)} \${letter}: <strong>\${escapeHtml(key)}</strong> — \${escapeHtml(desc)}</span>
                </div>
                <span class="mono" style="font-weight:700; font-size:13px; color:\${isWinner ? 'var(--codex-dark)' : 'var(--text-muted)'};">\${pct}%</span>
              </div>
              <div class="bar-track">
                <div class="bar-fill \${isWinner ? 'Codex' : 'Gemini'}" style="transform:scaleX(\${Math.max(0.02, Math.min(1, rawProb))}); opacity:\${isWinner ? 1 : 0.35};"></div>
              </div>
            </div>
          \`;
        }).join("");

        section2Html = \`
          <div class="insp-step-label">\${escapeHtml(t().step2Choice)}</div>
          <div class="insp-question-box">\${escapeHtml(evt.questionOrTitle)}</div>
          <div class="cand-list">\${candidatesHtml}</div>
        \`;
      } else {
        const metricLabels = t().metrics;

        const inputsHtml = optEntries.map(([k, v]) => \`
          <div style="font-size:12px; color:var(--text-slate); margin-bottom:4px;">
            <strong class="mono">\${escapeHtml(k)}:</strong> \${escapeHtml(v)}
          </div>
        \`).join("");

        const metricsHtml = Object.entries(probs).map(([mKey, mVal]) => {
          const rawProb = Number(mVal) || 0;
          const pct = Math.round(rawProb * 100);
          const isRisk = mKey.includes("risk") || mKey.includes("destructive") || mKey.includes("secret") || mKey.includes("flaw");
          const label = metricLabels[mKey] || mKey;
          return \`
            <div class="cand-item \${!isRisk && pct >= 70 ? 'winner' : ''}">
              <div class="cand-row-top">
                <div class="cand-left">
                  <span><strong>\${escapeHtml(label)}</strong></span>
                </div>
                <span class="mono" style="font-weight:700; font-size:13px;">\${pct}%</span>
              </div>
              <div class="bar-track">
                <div class="bar-fill \${isRisk ? 'CLI' : 'Codex'}" style="transform:scaleX(\${Math.max(0.02, Math.min(1, rawProb))});"></div>
              </div>
            </div>
          \`;
        }).join("");

        section2Html = \`
          <div class="insp-step-label">\${escapeHtml(t().step2Metrics)}</div>
          <div class="insp-question-box">
            <div style="margin-bottom:6px;">\${escapeHtml(evt.questionOrTitle)}</div>
            <div style="padding-top:6px; border-top:1px solid var(--border-light); font-weight:400;">\${inputsHtml}</div>
          </div>
          <div class="cand-list">\${metricsHtml}</div>
        \`;
      }

      const isProceed = evt.verdict === "AUTOPILOT_PROCEED" || evt.verdict === "ALLOW";
      const bannerTitle = isProceed
        ? t().bannerProceed(evt.agent, evt.selectedOption)
        : t().bannerAsk(evt.agent, evt.selectedOption);

      const directiveJson = {
        agent: evt.agent,
        project: evt.workspace,
        verdict: evt.verdict,
        selectedOption: evt.selectedOption,
        confidence: Number((evt.selectedProbability || 0).toFixed(2)),
        directive: evt.directive
      };

      bodyEl.innerHTML = \`
        <div class="insp-block">
          <div class="insp-step-label">\${escapeHtml(t().step1)}</div>
          <div class="row-badges" style="margin-bottom:8px;">
            <span class="badge-agent \${escapeHtml(evt.agent)}">\${escapeHtml(formatAgentBadgeText(evt.agent))}</span>
            <span class="badge-project">📁 \${escapeHtml(t().projectLabel)}: \${escapeHtml(evt.workspace)}</span>
            <span class="badge-project mono">🔧 \${escapeHtml(evt.tool)}</span>
          </div>
          <div class="path-banner mono">
            \${escapeHtml(t().projectPathLabel)}: \${escapeHtml(evt.workspacePath || evt.workspace)}
          </div>
        </div>

        <div class="insp-block">
          \${section2Html}
        </div>

        <div class="insp-block">
          <div class="insp-step-label">\${escapeHtml(t().step3)}</div>
          <div class="directive-alert \${isProceed ? 'proceed' : 'ask'}">
            <span>⚡</span>
            <span>\${escapeHtml(bannerTitle)}</span>
          </div>
          <div class="directive-code mono">\${escapeHtml(JSON.stringify(directiveJson, null, 2))}</div>

          <div class="feedback-box">
            <div style="font-size:12px; font-weight:700; color:var(--text-ink);">
              \${escapeHtml(t().fbTitle)} <span class="mono">\${escapeHtml(evt.workspace)}</span>
            </div>
            <div style="font-size:11.5px; color:var(--text-muted); margin-top:2px;">
              \${t().fbSub(escapeHtml(evt.workspace))}
            </div>
            <div class="feedback-actions">
              <button class="btn-fb-good" type="button" id="btnFbGood">\${escapeHtml(t().fbGoodBtn)}</button>
              <button class="btn-fb-bad" type="button" id="btnFbBad">\${escapeHtml(t().fbBadBtn)}</button>
            </div>
            <div id="fbStatusMsg" style="font-size:12px; font-weight:600; color:var(--codex-dark); margin-top:6px; display:none;"></div>
          </div>
        </div>
      \`;

      const fbStatus = document.getElementById("fbStatusMsg");
      document.getElementById("btnFbGood")?.addEventListener("click", async () => {
        const ruleText = \`[CONFIRMED GOOD on \${evt.tool}]: Verdict \${evt.verdict} is appropriate for pattern: \${evt.questionOrTitle.slice(0, 140)}\`;
        await submitProjectFeedback(evt.workspace, evt.workspacePath, evt.tool, "CORRECT", ruleText, evt.id);
        if (fbStatus) {
          fbStatus.style.display = "block";
          fbStatus.textContent = t().fbSavedGood(evt.workspace);
        }
      });

      document.getElementById("btnFbBad")?.addEventListener("click", async () => {
        const defaultCorrection =
          evt.verdict === "BLOCK" || evt.verdict === "ASK_USER"
            ? \`Do NOT block or flag false-positive on [\${evt.tool}] when executing authorized task: "\${evt.questionOrTitle.slice(0, 140)}" -> should ALLOW.\`
            : \`Be stricter on [\${evt.tool}] for pattern: "\${evt.questionOrTitle.slice(0, 140)}".\`;
        const userNote = window.prompt(t().fbPrompt(evt.workspace), defaultCorrection);
        if (!userNote || !userNote.trim()) return;
        await submitProjectFeedback(
          evt.workspace,
          evt.workspacePath,
          evt.tool,
          "FALSE_POSITIVE_OVERRIDE",
          userNote.trim(),
          evt.id
        );
        if (fbStatus) {
          fbStatus.style.display = "block";
          fbStatus.textContent = t().fbSavedRule(evt.workspace);
        }
      });
    }

    function renderSessionList() {
      const listEl = document.getElementById("sessionList");
      const filterLabel = document.getElementById("activeFilterLabel");
      filterLabel.textContent =
        (selectedAgentFilter === "ALL" ? t().allAgents : selectedAgentFilter) +
        " · " +
        (selectedWorkspaceFilter === "ALL" ? t().allWorkspaces : selectedWorkspaceFilter);

      const filtered = getFilteredEvents();
      if (filtered.length === 0) {
        listEl.innerHTML = \`
          <div style="text-align:center; padding:44px 16px; color:var(--text-muted); border:1px dashed var(--border-light); border-radius:10px;">
            \${t().emptyList}
          </div>
        \`;
        renderInspector(null);
        return;
      }

      if (!selectedEventId || !filtered.some((e) => e.id === selectedEventId)) {
        selectedEventId = filtered[0].id;
      }

      listEl.innerHTML = filtered.map((evt) => {
        const pct = Math.round((evt.selectedProbability || 0) * 100);
        const isSelected = evt.id === selectedEventId;
        return \`
          <article class="session-row-card \${isSelected ? 'selected' : ''}" data-id="\${escapeHtml(evt.id)}">
            <div>
              <div class="row-badges">
                <span class="badge-agent \${escapeHtml(evt.agent)}">\${escapeHtml(formatAgentBadgeText(evt.agent))}</span>
                <span class="badge-project">📁 \${escapeHtml(evt.workspace)}</span>
              </div>
              <div class="row-question">\${escapeHtml(evt.questionOrTitle)}</div>
            </div>

            <div class="outcome-col">
              <div class="outcome-top mono">
                <span class="outcome-option-name" title="\${escapeHtml(evt.selectedOption)}">\${escapeHtml(evt.selectedOption)}</span>
                <span>\${pct}%</span>
              </div>
              <div class="bar-track">
                <div class="bar-fill \${escapeHtml(evt.agent)}" data-scale="\${Math.max(0.05, Math.min(1, evt.selectedProbability || 0.9))}"></div>
              </div>
              <span class="verdict-chip \${escapeHtml(evt.verdict)}">\${escapeHtml(formatVerdictChipText(evt.verdict))}</span>
            </div>

            <div class="latency-col mono">
              <div>\${evt.latencyMs} ms</div>
              <div style="font-size:11px; color:var(--text-faint); font-weight:400; margin-top:2px;">\${escapeHtml(formatTime(evt.timestamp).split("·")[0])}</div>
            </div>
          </article>
        \`;
      }).join("");

      listEl.querySelectorAll(".bar-fill").forEach((bar) => {
        const s = parseFloat(bar.getAttribute("data-scale") || "0.9");
        if (window.gsap) {
          window.gsap.to(bar, { scaleX: s, duration: 0.45, ease: "power2.out" });
        } else {
          bar.style.transform = "scaleX(" + s + ")";
        }
      });

      const activeEvt = filtered.find((e) => e.id === selectedEventId) || filtered[0];
      renderInspector(activeEvt);
    }

    function showToast(evt) {
      const viewport = document.getElementById("toastViewport");
      const toast = document.createElement("div");
      toast.className = "white-toast";
      toast.setAttribute("data-agent", evt.agent);
      const pct = Math.round((evt.selectedProbability || 0) * 100);

      toast.innerHTML = \`
        <div class="toast-text">
          <strong>\${escapeHtml(formatAgentBadgeText(evt.agent))}</strong> \${t().toastAsked(escapeHtml(evt.workspace))}<br/>
          <span style="color:var(--codex-dark); font-size:12.5px;">\${escapeHtml(t().toastVerdictPrefix)}: \${escapeHtml(evt.selectedOption)} (\${pct}%) · \${escapeHtml(formatVerdictChipText(evt.verdict))}</span>
        </div>
        <button class="toast-close-btn" type="button">×</button>
      \`;

      toast.querySelector(".toast-close-btn").addEventListener("click", () => toast.remove());
      viewport.appendChild(toast);

      if (window.gsap) {
        window.gsap.fromTo(
          toast,
          { y: 18, opacity: 0 },
          { y: 0, opacity: 1, duration: 0.28, ease: "power2.out" }
        );
      }

      setTimeout(() => {
        if (!toast.isConnected) return;
        if (window.gsap) {
          window.gsap.to(toast, {
            y: 12,
            opacity: 0,
            duration: 0.2,
            onComplete: () => toast.remove()
          });
        } else {
          toast.remove();
        }
      }, 5500);

      if (desktopNotifyEnabled && "Notification" in window && Notification.permission === "granted") {
        new Notification(\`\${formatAgentBadgeText(evt.agent)} [\${evt.workspace}]\`, {
          body: \`\${evt.questionOrTitle}\\n\${t().toastVerdictPrefix}: \${evt.selectedOption} (\${pct}%)\`,
          tag: evt.id
        });
      }
    }

    async function loadInitialEvents() {
      const res = await fetch("/api/events?limit=100");
      const data = await res.json();
      allEvents = data.events || [];
      if (allEvents.length > 0) {
        selectedEventId = allEvents[0].id;
      }
      updateKpis(computeLocalStats(allEvents));
      renderSessionList();
    }

    function connectSse() {
      const statusEl = document.getElementById("sseStatusText");
      const es = new EventSource("/api/stream");
      es.onopen = () => {
        statusEl.textContent = t().sseConnected;
      };
      es.onmessage = (msg) => {
        try {
          const payload = JSON.parse(msg.data);
          if (payload.type === "new_event" && payload.event) {
            const evt = payload.event;
            if (!allEvents.some((x) => x.id === evt.id)) {
              allEvents.unshift(evt);
              selectedEventId = evt.id;
              updateKpis(computeLocalStats(allEvents));
              renderSessionList();
              showToast(evt);
            }
          }
        } catch {}
      };
      es.onerror = () => {
        statusEl.textContent = t().sseReconnecting;
      };
    }

    function setLanguage(lang) {
      currentLang = lang === "vi" ? "vi" : "en";
      try {
        localStorage.setItem("jev_lang", currentLang);
      } catch {}
      applyStaticTranslations();
      updateKpis(computeLocalStats(allEvents));
      renderSessionList();
    }

    document.getElementById("btnLangEn").addEventListener("click", () => setLanguage("en"));
    document.getElementById("btnLangVi").addEventListener("click", () => setLanguage("vi"));

    document.getElementById("sessionList").addEventListener("click", (e) => {
      const card = e.target.closest(".session-row-card[data-id]");
      if (!card) return;
      selectedEventId = card.getAttribute("data-id");
      renderSessionList();
    });

    document.getElementById("agentNav").addEventListener("click", (e) => {
      const btn = e.target.closest(".side-btn[data-agent-filter]");
      if (!btn) return;
      document.querySelectorAll("#agentNav .side-btn").forEach((b) => b.classList.remove("active"));
      btn.classList.add("active");
      selectedAgentFilter = btn.getAttribute("data-agent-filter") || "ALL";
      renderSessionList();
    });

    document.getElementById("workspaceNav").addEventListener("click", (e) => {
      const btn = e.target.closest(".ws-item[data-ws]");
      if (!btn) return;
      selectedWorkspaceFilter = btn.getAttribute("data-ws") || "ALL";
      renderWorkspaceSidebar();
      renderSessionList();
    });

    document.getElementById("searchInput").addEventListener("input", (e) => {
      searchQuery = (e.target.value || "").trim().toLowerCase();
      renderSessionList();
    });

    document.getElementById("btnSimCodex").addEventListener("click", async (e) => {
      const btn = e.currentTarget;
      btn.disabled = true;
      try {
        await fetch("/api/simulate", {
          method: "POST",
          headers: { "Content-Type": "application/json", "X-Jev-CSRF": JEV_CSRF_TOKEN },
          body: JSON.stringify({ agent: "Codex", lang: currentLang })
        });
      } finally {
        btn.disabled = false;
      }
    });

    document.getElementById("btnSimGemini").addEventListener("click", async (e) => {
      const btn = e.currentTarget;
      btn.disabled = true;
      try {
        await fetch("/api/simulate", {
          method: "POST",
          headers: { "Content-Type": "application/json", "X-Jev-CSRF": JEV_CSRF_TOKEN },
          body: JSON.stringify({ agent: "Gemini", lang: currentLang })
        });
      } finally {
        btn.disabled = false;
      }
    });

    document.getElementById("btnNotify").addEventListener("click", async () => {
      if (!("Notification" in window)) return;
      const perm = await Notification.requestPermission();
      if (perm === "granted") {
        desktopNotifyEnabled = true;
        document.getElementById("notifyLabel").textContent = t().enabledNotify;
      }
    });

    document.getElementById("btnClear").addEventListener("click", async () => {
      await fetch("/api/events", { method: "DELETE", headers: { "X-Jev-CSRF": JEV_CSRF_TOKEN } });
      allEvents = [];
      selectedEventId = null;
      updateKpis(computeLocalStats([]));
      renderSessionList();
    });

    async function submitProjectFeedback(workspaceName, workspacePath, tool, feedbackType, rule, eventId) {
      await fetch("/api/feedback", {
        method: "POST",
        headers: { "Content-Type": "application/json", "X-Jev-CSRF": JEV_CSRF_TOKEN },
        body: JSON.stringify({
          workspaceName,
          workspacePath,
          tool,
          feedbackType,
          rule,
          eventId
        })
      });
    }

    async function openProjectBrainModal() {
      const overlay = document.getElementById("brainModalOverlay");
      const bodyEl = document.getElementById("brainModalBody");
      overlay.classList.add("open");
      bodyEl.innerHTML = \`<div style="padding:24px; text-align:center; color:var(--text-muted);">\${escapeHtml(t().loadingBrain)}</div>\`;

      const res = await fetch("/api/projects");
      const data = await res.json();
      const profiles = data.profiles || [];

      if (profiles.length === 0) {
        bodyEl.innerHTML = \`<div style="padding:24px; text-align:center; color:var(--text-muted);">\${escapeHtml(t().emptyBrain)}</div>\`;
        return;
      }

      bodyEl.innerHTML = profiles.map((p) => {
        const overrides = Array.isArray(p.learnedHumanOverrides) ? p.learnedHumanOverrides : [];
        const overridesHtml = overrides.length > 0
          ? overrides.map((o) => \`
              <div style="display:flex; align-items:center; justify-content:space-between; gap:10px; background:var(--bg-white); border:1px solid var(--border-light); border-radius:7px; padding:7px 10px; margin-top:6px; font-size:12px;">
                <div>
                  <span class="badge-project mono" style="margin-right:6px;">\${escapeHtml(o.feedbackType)}</span>
                  <span>\${escapeHtml(o.rule)}</span>
                </div>
                <button class="btn-white" style="padding:3px 8px; font-size:11px;" data-del-ws="\${escapeHtml(p.workspaceName)}" data-del-id="\${escapeHtml(o.id)}" type="button">\${escapeHtml(t().deleteBtn)}</button>
              </div>
            \`).join("")
          : \`<div style="font-size:12px; color:var(--text-muted); margin-top:4px;">\${escapeHtml(t().noCustomRules)}</div>\`;

        return \`
          <div class="brain-project-card">
            <div style="display:flex; align-items:center; justify-content:space-between; gap:10px; margin-bottom:8px;">
              <div>
                <span style="font-size:15px; font-weight:700; color:var(--text-ink);">📁 \${escapeHtml(p.workspaceName)}</span>
                <span class="mono" style="font-size:11.5px; color:var(--text-muted); margin-left:8px;">\${escapeHtml(p.workspacePath || "")}</span>
              </div>
              <button class="btn-emerald" style="padding:4px 10px; font-size:11.5px;" data-add-rule-ws="\${escapeHtml(p.workspaceName)}" data-add-rule-path="\${escapeHtml(p.workspacePath || "")}" type="button">\${escapeHtml(t().addRuleBtn)}</button>
            </div>
            <div style="font-size:12px; color:var(--text-slate); margin-bottom:4px;">
              <strong>Tech Stack:</strong> <span class="mono">\${escapeHtml(p.stackSummary || "generic")}</span>
            </div>
            \${p.repoTopology ? \`<div style="font-size:12px; color:var(--text-slate); margin-bottom:4px;"><strong>\${escapeHtml(t().topologyLabel)}:</strong> <span class="mono">\${escapeHtml(p.repoTopology)}</span></div>\` : ""}
            \${p.domainAndAuthFingerprint ? \`<div style="font-size:12px; color:var(--codex-dark); margin-bottom:6px;"><strong>\${escapeHtml(t().domainAuthLabel)}:</strong> <span class="mono">\${escapeHtml(p.domainAndAuthFingerprint)}</span></div>\` : ""}
            <div style="margin-top:8px; padding-top:8px; border-top:1px solid var(--border-light);">
              <div style="font-size:11.5px; font-weight:700; color:var(--text-ink); text-transform:uppercase;">\${escapeHtml(t().learnedRulesHeader(overrides.length))}</div>
              \${overridesHtml}
            </div>
          </div>
        \`;
      }).join("");
    }

    document.getElementById("btnOpenBrain").addEventListener("click", openProjectBrainModal);
    document.getElementById("btnCloseBrain").addEventListener("click", () => {
      document.getElementById("brainModalOverlay").classList.remove("open");
    });
    document.addEventListener("keydown", (e) => {
      if (e.key === "Escape") {
        document.getElementById("brainModalOverlay").classList.remove("open");
      }
    });

    document.getElementById("brainModalBody").addEventListener("click", async (e) => {
      const addBtn = e.target.closest("[data-add-rule-ws]");
      if (addBtn) {
        const ws = addBtn.getAttribute("data-add-rule-ws");
        const wsPath = addBtn.getAttribute("data-add-rule-path");
        const rule = window.prompt(t().addRulePrompt(ws));
        if (rule && rule.trim()) {
          await submitProjectFeedback(ws, wsPath, "all_tools", "CUSTOM_RULE", rule.trim());
          await openProjectBrainModal();
        }
        return;
      }

      const delBtn = e.target.closest("[data-del-id]");
      if (delBtn) {
        const ws = delBtn.getAttribute("data-del-ws");
        const ruleId = delBtn.getAttribute("data-del-id");
        await fetch("/api/projects/rule", {
          method: "DELETE",
          headers: { "Content-Type": "application/json", "X-Jev-CSRF": JEV_CSRF_TOKEN },
          body: JSON.stringify({ workspaceName: ws, ruleId })
        });
        await openProjectBrainModal();
      }
    });

    applyStaticTranslations();
    loadInitialEvents().then(connectSse);
  </script>
</body>
</html>`;
}
