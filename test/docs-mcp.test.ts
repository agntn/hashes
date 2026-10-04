import { readdirSync, readFileSync } from "node:fs";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import type { CallToolResult } from "@modelcontextprotocol/sdk/types.js";
import { describe, expect, it, vi } from "vite-plus/test";
import { callTool, toolListings } from "../src/mcp.ts";

/* The toolkit's entry drags in Nitro, and `defineMcpTool` only hands its input back. */
vi.mock(
  "../docs/node_modules/@nuxtjs/mcp-toolkit/dist/runtime/server/mcp/definitions/index.js",
  () => ({
    defineMcpTool: (definition: unknown) => definition,
  }),
);

const toolsDir = new URL("../docs/server/mcp/tools/", import.meta.url);

/* An SDK client on every docs tool, registered the way the toolkit does it. */
async function docsClient(): Promise<Client> {
  const { hashesMcpTool } = await import("../docs/server/utils/hashes-mcp.ts");
  const server = new McpServer({ name: "docs", version: "0.0.0" });
  for (const listing of toolListings) {
    const tool = hashesMcpTool(listing.name);
    const handler = tool.handler as (
      args: Readonly<Record<string, unknown>>,
    ) => Promise<CallToolResult>;
    server.registerTool(listing.name, tool, handler);
  }
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  const client = new Client({ name: "test", version: "0.0.0" });
  await Promise.all([server.connect(serverTransport), client.connect(clientTransport)]);
  return client;
}

describe("docs MCP tools", () => {
  it("serves every tool `hashes mcp` lists, one file each", () => {
    const files = readdirSync(toolsDir).toSorted();
    expect(files).toEqual(
      toolListings.map((tool) => `${tool.name.replaceAll("_", "-")}.ts`).toSorted(),
    );
    for (const file of files) {
      const name = file.slice(0, -".ts".length).replaceAll("-", "_");
      expect(readFileSync(new URL(file, toolsDir), "utf8")).toBe(
        `export default hashesMcpTool(${JSON.stringify(name)});\n`,
      );
    }
  });

  it("reads a call without arguments as `{}`, like `hashes mcp`", async () => {
    const client = await docsClient();
    const served = await client.callTool({ name: "hashes_algorithms" });
    expect(served.isError).toBeFalsy();
    expect(served.content).toEqual((await callTool("hashes_algorithms", {})).content);

    const required = await client.callTool({ name: "hashes_compute" });
    expect(required.isError).toBe(true);
    expect(required.content).toEqual((await callTool("hashes_compute", {})).content);
  });
});
