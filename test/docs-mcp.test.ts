import type { ToolkitTool } from "@agntn/tools/toolkit";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import type { CallToolResult } from "@modelcontextprotocol/sdk/types.js";
import { describe, expect, it, vi } from "vite-plus/test";
import { callTool, toolListings } from "../src/mcp.ts";

/* The toolkit's entry drags in Nitro, so the handler gets its page tools and options here. */
vi.mock(
  "../docs/node_modules/@nuxtjs/mcp-toolkit/dist/runtime/server/mcp/definitions/index.js",
  () => ({
    defineMcpHandler: (options: unknown) => options,
    getMcpTools: async () => [{ name: "list-pages" }, { name: "get-page" }],
  }),
);

/* What `server/mcp/index.ts` serves for one request, Docus page tools included. */
async function docsTools(): Promise<ReadonlyArray<Readonly<ToolkitTool>>> {
  const { default: handler } = await import("../docs/server/mcp/index.ts");
  const { tools } = handler;
  if (typeof tools !== "function") throw new TypeError("the handler should resolve its tools");
  return (await tools(undefined as never)) as ToolkitTool[];
}

/* An SDK v1 client on every hash tool, registered the way the toolkit does it. */
async function docsClient(): Promise<Client> {
  const server = new McpServer({ name: "docs", version: "0.0.0" });
  for (const tool of await docsTools()) {
    if (!tool.name.startsWith("hashes_")) continue;
    const handler = tool.handler as (args: unknown) => Promise<CallToolResult>;
    server.registerTool(tool.name, tool as never, handler);
  }
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  const client = new Client({ name: "test", version: "0.0.0" });
  await Promise.all([server.connect(serverTransport), client.connect(clientTransport)]);
  return client;
}

describe("docs MCP tools", () => {
  it("serves every tool `hashes mcp` lists after the Docus page tools", async () => {
    expect((await docsTools()).map((tool) => tool.name)).toEqual([
      "list-pages",
      "get-page",
      ...toolListings.map((tool) => tool.name),
    ]);
    const listed = (await (await docsClient()).listTools()).tools;
    /* SDK v1 adds `$schema` to every listed schema; the rest is the listing as written. */
    const schemas = listed.map(({ name, inputSchema }) => ({
      name,
      schema: { ...inputSchema, $schema: undefined },
    }));
    expect(schemas).toEqual(
      toolListings.map(({ name, inputSchema }) => ({ name, schema: inputSchema })),
    );
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

  it("answers a bad key in the library's sanitized words, not Zod's", async () => {
    const client = await docsClient();
    const args = { algorithm: "md5", input: "x", "a‮b": 1 };
    const served = await client.callTool({ name: "hashes_compute", arguments: args });
    expect(served.isError).toBe(true);
    expect(served.content).toEqual((await callTool("hashes_compute", args)).content);
    expect(JSON.stringify(served.content)).not.toContain("‮");
  });

  it("holds a KDF to the worker's 64 MiB", async () => {
    const client = await docsClient();
    const args = {
      algorithm: "argon2id",
      input: "x",
      salt: "73616c7473616c74",
      parameters: { memory: 262_144 },
    };
    const served = await client.callTool({ name: "hashes_compute", arguments: args });
    expect(served.isError).toBe(true);
    expect(served.content).toEqual(
      (await callTool("hashes_compute", args, { maxMemory: 64 * 1024 * 1024 })).content,
    );
  });
});
