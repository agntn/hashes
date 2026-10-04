import { callTool, toolListings } from "@agntn/hashes/mcp";
import {
  defineMcpTool,
  type McpToolDefinition,
  type McpToolDefinitionListItem,
} from "@nuxtjs/mcp-toolkit/server";
import { z } from "zod";

/** Most bytes a KDF may fill here, half the 128 MB a Workers isolate gets. */
const WORKER_MEMORY = 64 * 1024 * 1024;

/**
 * A `hashes mcp` tool for Docus: its own schema in `tools/list`, its own checks on the call.
 *
 * @param {string} name - The tool's name, such as `hashes_compute`.
 * @returns {McpToolDefinitionListItem} The tool definition for `server/mcp/tools/`.
 */
export function hashesMcpTool(name: string): McpToolDefinitionListItem {
  const listing = toolListings.find((candidate) => candidate.name === name);
  if (listing === undefined) {
    throw new Error(`Unknown hashes tool: ${name}`);
  }
  /** Zod lets any object by, so a stray key reaches `callTool` and comes back sanitized. */
  const schema = z.looseObject({});
  schema._zod.toJSONSchema = () => ({ ...listing.inputSchema });
  /** The SDK hands Zod a missing `arguments` untouched, so read it as the `{}` stdio gets. */
  const run = schema._zod.run.bind(schema._zod);
  schema._zod.run = (payload, context) =>
    run(payload.value === undefined ? { ...payload, value: {} } : payload, context);
  /** The toolkit types a raw shape only, while the SDK it hands the schema to takes an object too. */
  const inputSchema = schema as unknown as NonNullable<McpToolDefinition["inputSchema"]>;
  return defineMcpTool({
    name: listing.name,
    title: listing.title,
    description: listing.description,
    annotations: listing.annotations,
    inputSchema,
    handler: (args: Readonly<Record<string, unknown>>, extra) =>
      callTool(name, args, { signal: extra.signal, maxMemory: WORKER_MEMORY }),
  });
}
