import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { defineCommand } from "citty";
import { createMcpServer } from "../mcp.ts";

export default defineCommand({
  meta: {
    name: "mcp",
    description: "Run the hashes MCP server over stdio",
  },
  async run() {
    await createMcpServer().connect(new StdioServerTransport());
  },
});
