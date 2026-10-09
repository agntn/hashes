import { sanitizeLine, wireSchema, type ToolDefinition, type ToolResult } from "@agntn/tools";
import {
  callTool as answerCall,
  createMcpServer as createToolServer,
  toolAnnotations,
} from "@agntn/tools/mcp";
import type { CallToolResult, Server, Tool } from "@modelcontextprotocol/server";
import { MAX_SCRYPT_MEMORY } from "../packages/shared/tool-contract.ts";
import { serverInfo } from "./server-info.ts";
import { hashesTools } from "./tools.ts";

/** The `tools/list` entries `hashes mcp` answers with. */
export const toolListings: readonly Tool[] = hashesTools.map((tool) => ({
  name: tool.name,
  title: tool.title,
  description: tool.description,
  inputSchema: { ...wireSchema(tool), type: "object" },
  annotations: toolAnnotations(tool),
}));

/** What a host running the tools for someone else can add to a call. */
export interface CallToolOptions {
  /** Passed to the tool as is; the synchronous executors finish within their limits anyway. */
  readonly signal?: Readonly<AbortSignal>;
  /** Most bytes a KDF may fill, below the tool limits, for a host with less memory. */
  readonly maxMemory?: number;
}

/**
 * Runs one tool the way `tools/call` of `hashes mcp` does, errors as results, never as a throw.
 *
 * @param {string} name - The tool's name, such as `hashes_compute`.
 * @param {Readonly<Record<string, unknown>>} args - The arguments the client sent.
 * @param {CallToolOptions} [options] - A signal, and a memory cap tighter than the tool limits.
 * @returns {Promise<CallToolResult>} The tool's text, or the sanitized error.
 */
export async function callTool(
  name: string,
  args: Readonly<Record<string, unknown>>,
  options: Readonly<CallToolOptions> = {},
): Promise<CallToolResult> {
  const { signal, maxMemory } = options;
  const tools = maxMemory === undefined ? hashesTools : memoryCappedTools(maxMemory);
  return await answerCall(serverInfo, tools, name, args, signal === undefined ? {} : { signal });
}

/**
 * The tools with every KDF held to `maxMemory` bytes, for a host as tight as a Workers isolate.
 *
 * @param {number} maxMemory - Most bytes a KDF may fill.
 * @returns {ToolDefinition[]} The tools in `hashesTools` order; a costlier KDF never allocates.
 */
export function memoryCappedTools(maxMemory: number): ToolDefinition[] {
  return hashesTools.map((tool) => ({
    ...tool,
    execute: async (input, context) =>
      (await overMemory(tool.name, input, maxMemory)) ?? (await tool.execute(input, context)),
  }));
}

/**
 * Refuses a KDF over `maxMemory` as a result; a thrown class fails another copy's `instanceof`.
 *
 * @param {string} name - The tool's name.
 * @param {Readonly<Record<string, unknown>>} args - The arguments, already past the schema.
 * @param {number} maxMemory - Most bytes the host allows.
 * @returns {Promise<ToolResult | undefined>} The sanitized error, or nothing when the call fits.
 */
async function overMemory(
  name: string,
  args: Readonly<Record<string, unknown>>,
  maxMemory: number,
): Promise<ToolResult | undefined> {
  const { kdfMemory } = await import("./tool-operations.ts");
  const memory = kdfMemory(args);
  if (memory <= maxMemory) return undefined;
  const lines = [
    `${name} failed: ${String(args["algorithm"])} needs ${memory} bytes of memory, over the ${maxMemory} this server allows`,
    `Lower its memory cost, or run npx -y @agntn/hashes mcp, which takes up to ${MAX_SCRYPT_MEMORY}`,
  ];
  const text = lines.map(sanitizeLine).join("\n");
  return { content: [{ type: "text", text }], details: undefined, isError: true };
}

/**
 * Creates an unconnected MCP server exposing the hash tools.
 *
 * @returns {Server} Unconnected MCP server.
 */
export function createMcpServer(): Server {
  return createToolServer(serverInfo, hashesTools);
}
