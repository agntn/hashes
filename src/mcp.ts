import { createMcpServer as createToolServer } from "@agntn/tools/mcp";
import type { Server } from "@modelcontextprotocol/server";
import { hashesTools } from "./tools.ts";
import { version } from "./version.ts";

/**
 * Creates an unconnected MCP server exposing the hash tools.
 *
 * @returns {Server} Unconnected MCP server.
 */
export function createMcpServer(): Server {
  return createToolServer({ name: "hashes", version }, hashesTools);
}
