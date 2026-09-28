#!/usr/bin/env node

import { existsSync } from "node:fs";
import { sep } from "node:path";
import { fileURLToPath } from "node:url";
import type { ArgsDef, CommandDef } from "citty";
import type McpCommand from "./commands/mcp.ts";
import { normalizeMainArgs } from "./cli-args.ts";
import { HashError } from "./core/errors.ts";
import { version } from "./version.ts";

/**
 * citty colors its usage and its errors even into a pipe, takes `NO_COLOR` only as `1`, and decides
 * once, as it loads, so `hashes --help | less`, a file or an agent's transcript gets the escapes.
 * The terminal decides here, before citty loads: colors only when both streams citty writes to are
 * terminals that take them, and `hasColors()` already honors any `NO_COLOR` and `TERM=dumb`.
 */
const { stderr, stdout } = process;
if (!(stdout.isTTY && stdout.hasColors() && stderr.isTTY && stderr.hasColors())) {
  process.env["NO_COLOR"] = "1";
}
const { defineCommand, runMain } = await import("citty");

/**
 * Ends the process once the reader of stdout or stderr is gone, as after `| head -1` or a pager
 * that quits early. Node ignores SIGPIPE, so without a listener the next write throws `EPIPE`
 * with a stack trace. The exit code stays whatever the command set.
 *
 * @param error - The error the stream emitted.
 */
function exitOnClosedPipe(error: Readonly<NodeJS.ErrnoException>): void {
  if (error.code !== "EPIPE") throw error;
  process.exit();
}

stdout.on("error", exitOnClosedPipe);
stderr.on("error", exitOnClosedPipe);

/**
 * Loads a command and turns the library's own errors into one line on stderr with exit code 1;
 * citty would print them with a stack trace and every field.
 *
 * @param loader - Imports the command module.
 * @returns {Promise<CommandDef<T>>} The command with its `run` guarded.
 */
async function command<T extends ArgsDef>(
  loader: () => Promise<{ readonly default: CommandDef<T> }>,
): Promise<CommandDef<T>> {
  const loaded = (await loader()).default;
  const run = loaded.run;
  if (!run) return loaded;
  return {
    ...loaded,
    async run(context) {
      try {
        const result: unknown = await run(context);
        return result;
      } catch (error) {
        if (!(error instanceof HashError)) throw error;
        stderr.write(`${error.message}\n`);
        process.exitCode = 1;
        return undefined;
      }
    },
  };
}

/** The same file from `src/cli.ts` and `dist/cli.mjs`; the npm package ships only `dist`. */
const sourceMcpCommand = new URL("../src/commands/mcp.ts", import.meta.url);
const sourceMcpCommandPath = fileURLToPath(sourceMcpCommand);

/**
 * Narrows the module a runtime URL import returned, which TypeScript types as `any`.
 *
 * @param value - The imported module namespace.
 * @returns {value is { default: typeof McpCommand }} Whether it exports a default command.
 */
function isCommandModule(value: unknown): value is { default: typeof McpCommand } {
  return typeof value === "object" && value !== null && "default" in value;
}

/**
 * Loads the MCP command. A built bin inside a checkout runs the live source, like the Pi and OMP
 * extensions, so a local server needs a restart after a change instead of `pnpm build`. Node
 * never strips types under `node_modules`, so an installed copy keeps the bundle, and
 * `HASHES_DIST=1` keeps it everywhere, for tests of the built output. The URL is built at
 * runtime so the bundler leaves `src` out.
 *
 * @returns {Promise<{ default: typeof McpCommand }>} The module holding the stdio server command.
 */
async function loadMcpCommand(): Promise<{ default: typeof McpCommand }> {
  const fromSource =
    !import.meta.url.endsWith(".ts") &&
    process.env["HASHES_DIST"] !== "1" &&
    !sourceMcpCommandPath.includes(`${sep}node_modules${sep}`) &&
    existsSync(sourceMcpCommandPath);
  if (!fromSource) return import("./commands/mcp.ts");
  const module: unknown = await import(sourceMcpCommand.href);
  if (!isCommandModule(module)) {
    throw new TypeError(`${sourceMcpCommandPath} has no default command`);
  }
  return module;
}

const main = defineCommand({
  meta: {
    name: "hashes",
    version,
    description: "Hash, HMAC, verify and look up hash and key derivation algorithms",
  },
  subCommands: {
    hash: () => command(() => import("./commands/hash.ts")),
    hmac: () => command(() => import("./commands/hmac.ts")),
    verify: () => command(() => import("./commands/verify.ts")),
    algorithms: () => command(() => import("./commands/algorithms.ts")),
    info: () => command(() => import("./commands/info.ts")),
    mcp: () => command(loadMcpCommand),
  },
});

await runMain(main, { rawArgs: normalizeMainArgs(process.argv.slice(2)) });
