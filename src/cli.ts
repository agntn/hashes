#!/usr/bin/env node

import { existsSync } from "node:fs";
import { sep } from "node:path";
import { fileURLToPath } from "node:url";
import { runCli } from "@agntn/tools/cli";
import { cliCommands } from "./cli-commands.ts";
import { HashError } from "./core/errors.ts";
import type { createMcpServer } from "./mcp.ts";
import { hashesTools } from "./tools.ts";
import { version } from "./version.ts";

/** The same file from `src/cli.ts` and `dist/cli.mjs`; the npm package ships only `dist`. */
const sourceMcp = new URL("../src/mcp.ts", import.meta.url);
const sourceMcpPath = fileURLToPath(sourceMcp);

/**
 * Narrows the module a runtime URL import returned, which TypeScript types as `any`.
 *
 * @param value - The imported module namespace.
 * @returns {value is { createMcpServer: typeof createMcpServer }} Whether it exports the server.
 */
function isMcpModule(value: unknown): value is { createMcpServer: typeof createMcpServer } {
  return typeof value === "object" && value !== null && "createMcpServer" in value;
}

/**
 * A built bin inside a checkout serves the live source, like the Pi and OMP extensions, so a local
 * server needs a restart after a change instead of `pnpm build`. Node never strips types under
 * `node_modules`, so an installed copy keeps the bundle, and `HASHES_DIST=1` keeps it everywhere,
 * for tests of the built output.
 *
 * @returns {boolean} Whether the source is there to serve.
 */
function servesSource(): boolean {
  return (
    !import.meta.url.endsWith(".ts") &&
    process.env["HASHES_DIST"] !== "1" &&
    !sourceMcpPath.includes(`${sep}node_modules${sep}`) &&
    existsSync(sourceMcpPath)
  );
}

/**
 * Serves `createMcpServer` over stdio rather than the `mcp` of `runCli`, which can't show the
 * description and icons yet. The source URL is built at runtime, so the bundler leaves `src` out.
 *
 * @returns {Promise<void>} Once the server is connected.
 */
async function serveMcp(): Promise<void> {
  const module: unknown = servesSource() ? await import(sourceMcp.href) : await import("./mcp.ts");
  if (!isMcpModule(module)) throw new TypeError("The MCP module has no createMcpServer");
  const { StdioServerTransport } = await import("@modelcontextprotocol/server/stdio");
  await module.createMcpServer().connect(new StdioServerTransport());
}

/**
 * The library's own refusals print as one line; anything else is a bug and keeps its stack.
 *
 * @param error - What a command threw.
 * @returns {boolean} Whether it prints as one line instead of a stack trace.
 */
function isRefusal(error: unknown): boolean {
  return error instanceof HashError;
}

const argv = process.argv.slice(2);
if (argv.length === 1 && argv[0] === "mcp") {
  await serveMcp();
} else {
  await runCli(
    {
      name: "hashes",
      version,
      description: "Hash, HMAC, verify and look up hash and key derivation algorithms",
      tools: hashesTools,
      commands: cliCommands,
      default: "algorithms",
      fallback: "hash",
      mcp: true,
      expected: isRefusal,
    },
    argv,
  );
}
