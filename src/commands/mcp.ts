import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { defineCommand } from "citty";
import { consola, LogLevels } from "consola";
import { createMcpServer } from "../mcp.ts";

export default defineCommand({
  meta: {
    name: "mcp",
    description: "Run the hashes MCP server over stdio",
  },
  /**
   * stdout carries the JSON-RPC frames. consola's default reporter sends
   * anything at log level or below to that same descriptor, and `DEBUG` in the
   * environment raises the level on import, so one stray line would corrupt
   * the stream. Warnings and errors still reach stderr.
   */
  async run() {
    consola.level = LogLevels.warn;

    await createMcpServer().connect(new StdioServerTransport());
  },
});
