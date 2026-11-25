#!/usr/bin/env node
import fs from "node:fs";
import { runPreToolHook } from "./hook-runner.js";

const MAX_STDIN_BYTES = 2 * 1024 * 1024;

function readBoundedStdin(maxBytes = MAX_STDIN_BYTES): Promise<string> {
  return new Promise((resolve) => {
    if (process.stdin.isTTY) {
      resolve("");
      return;
    }
    const chunks: Buffer[] = [];
    let total = 0;
    let settled = false;
    const finish = () => {
      if (settled) return;
      settled = true;
      resolve(Buffer.concat(chunks).toString("utf8"));
    };
    process.stdin.on("data", (chunk: Buffer | string) => {
      const buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk, "utf8");
      if (total < maxBytes) {
        const remaining = maxBytes - total;
        chunks.push(buf.length <= remaining ? buf : buf.subarray(0, remaining));
        total += Math.min(buf.length, remaining);
      }
    });
    process.stdin.on("end", finish);
    process.stdin.on("error", finish);
  });
}

function getArgValue(args: string[], flag: string): string | undefined {
  const idx = args.indexOf(flag);
  if (idx !== -1 && idx + 1 < args.length) {
    return args[idx + 1];
  }
  return undefined;
}

async function main(): Promise<void> {
  const args = process.argv.slice(2);
  const cmdArg = getArgValue(args, "--command");
  const fileArg = getArgValue(args, "--file");
  let rawPayload = "";

  if (cmdArg) {
    rawPayload = JSON.stringify({ command: cmdArg });
  } else if (fileArg && fs.existsSync(fileArg)) {
    rawPayload = JSON.stringify({
      file_path: fileArg,
      code: fs.readFileSync(fileArg, "utf8").slice(0, MAX_STDIN_BYTES)
    });
  } else {
    rawPayload = await readBoundedStdin();
  }

  const result = await runPreToolHook(rawPayload);
  if (result.stdout) {
    process.stdout.write(`${result.stdout}\n`);
  }
  if (result.stderr) {
    process.stderr.write(`${result.stderr}\n`);
  }
  process.exit(result.exitCode);
}

main().catch((err) => {
  console.error("[jev-gate fatal]:", err instanceof Error ? err.message : String(err));
  process.exit(1);
});
