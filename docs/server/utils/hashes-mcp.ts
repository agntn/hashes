import { callTool, toolListings } from "@agntn/hashes/mcp";
import {
  defineMcpTool,
  type McpToolDefinition,
  type McpToolDefinitionListItem,
} from "@nuxtjs/mcp-toolkit/server";
import { z } from "zod";

/**
 * A `hashes mcp` tool for Docus, its schema read into Zod whole, since a shape strips unknown keys.
 *
 * @param {string} name - The tool's name, such as `hashes_compute`.
 * @returns {McpToolDefinitionListItem} The tool definition for `server/mcp/tools/`.
 */
export function hashesMcpTool(name: string): McpToolDefinitionListItem {
  const listing = toolListings.find((candidate) => candidate.name === name);
  if (listing === undefined) {
    throw new Error(`Unknown hashes tool: ${name}`);
  }
  const schema = z.fromJSONSchema(listing.inputSchema as z.core.JSONSchema.JSONSchema);
  /** The toolkit types a raw shape only, while the SDK it hands the schema to takes an object too. */
  const inputSchema = schema as unknown as NonNullable<McpToolDefinition["inputSchema"]>;
  return defineMcpTool({
    name: listing.name,
    title: listing.title,
    description: listing.description,
    annotations: listing.annotations,
    inputSchema,
    handler: (args: Readonly<Record<string, unknown>>, extra) =>
      callTool(name, args, extra.signal),
  });
}
