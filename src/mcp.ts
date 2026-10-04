import { indexTools, invokeTool, ToolInputError, wireSchema } from "@agntn/tools";
import {
  createMcpServer as createToolServer,
  errorResult,
  toolAnnotations,
} from "@agntn/tools/mcp";
import type { CallToolResult, Server, Tool } from "@modelcontextprotocol/server";
import { MAX_SCRYPT_MEMORY } from "../packages/shared/tool-contract.ts";
import { hashesTools } from "./tools.ts";
import { version } from "./version.ts";

/** The `tools/list` entries shared by `hashes mcp` and the MCP server of the docs site. */
export const toolListings: readonly Tool[] = hashesTools.map((tool) => ({
  name: tool.name,
  title: tool.title,
  description: tool.description,
  inputSchema: { ...wireSchema(tool), type: "object" },
  annotations: toolAnnotations(tool),
}));

const toolsByName = indexTools(hashesTools);

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
  const tool = toolsByName.get(name);
  if (!tool) return errorResult(`Unknown hashes tool: ${JSON.stringify(name)}`);
  const { signal, maxMemory } = options;
  const refusal = await overMemory(name, args, maxMemory);
  if (refusal !== undefined) return refusal;

  try {
    const result = await invokeTool(tool, args, signal === undefined ? {} : { signal });
    return {
      content: result.content,
      ...(result.isError === undefined ? {} : { isError: result.isError }),
    };
  } catch (error) {
    if (error instanceof ToolInputError) return errorResult(...error.lines);
    return errorResult(
      `${tool.name} failed: ${error instanceof Error ? error.message : String(error)}`,
    );
  }
}

/**
 * Refuses a KDF that would fill more than `maxMemory` bytes, before it allocates any of them.
 *
 * @param {string} name - The tool's name.
 * @param {Readonly<Record<string, unknown>>} args - The arguments the client sent.
 * @param {number} [maxMemory] - Most bytes the host allows, none for the tool limits alone.
 * @returns {Promise<CallToolResult | undefined>} The error, or nothing when the call fits.
 */
async function overMemory(
  name: string,
  args: Readonly<Record<string, unknown>>,
  maxMemory: number | undefined,
): Promise<CallToolResult | undefined> {
  if (maxMemory === undefined) return undefined;
  const { kdfMemory } = await import("./tool-operations.ts");
  const memory = kdfMemory(args);
  if (memory <= maxMemory) return undefined;
  return errorResult(
    `${name} failed: ${String(args["algorithm"])} needs ${memory} bytes of memory, over the ${maxMemory} this server allows`,
    `Lower its memory cost, or run npx -y @agntn/hashes mcp, which takes up to ${MAX_SCRYPT_MEMORY}`,
  );
}

/**
 * Creates an unconnected MCP server exposing the hash tools.
 *
 * @returns {Server} Unconnected MCP server.
 */
export function createMcpServer(): Server {
  return createToolServer({ name: "hashes", version }, hashesTools);
}
