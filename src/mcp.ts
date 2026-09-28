import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
  type CallToolResult,
  type Tool,
} from "@modelcontextprotocol/sdk/types.js";
import type { TSchema } from "typebox";
import type { TLocalizedValidationError } from "typebox/error";
import { Value } from "typebox/value";
import { toolSchemas } from "../packages/shared/tool-schemas.ts";
import {
  TOOL_DESCRIPTIONS,
  TOOL_TITLES,
  hashAlgorithms,
  hashCompute,
  hashHmac,
  hashVerify,
  type HashAlgorithmsParams,
  type HashComputeParams,
  type HashHmacParams,
  type HashVerifyParams,
  type ToolName,
  type ToolResult,
} from "./tool-operations.ts";
import { version } from "./version.ts";

interface ToolDefinition {
  readonly name: ToolName;
  execute(args: Readonly<Record<string, unknown>>): ToolResult<unknown>;
}

/** Arguments reach an executor only after `Value.Check` passed against the tool's schema. */
const tools: readonly ToolDefinition[] = [
  { name: "hash_compute", execute: (args) => hashCompute(args as HashComputeParams) },
  { name: "hash_hmac", execute: (args) => hashHmac(args as HashHmacParams) },
  { name: "hash_verify", execute: (args) => hashVerify(args as HashVerifyParams) },
  { name: "hash_algorithms", execute: (args) => hashAlgorithms(args as HashAlgorithmsParams) },
];

/**
 * The tool's schema, widened to what the MCP types and `Value` take.
 *
 * @param name - The tool.
 * @returns {TSchema} Its closed argument schema.
 */
function schemaOf(name: ToolName): TSchema {
  return toolSchemas[name];
}

/** Every tool is a local computation: it reads nothing and changes nothing. */
const annotations = {
  readOnlyHint: true,
  destructiveHint: false,
  idempotentHint: true,
  openWorldHint: false,
} as const;

/**
 * Names each key the schema does not declare, with the keys it takes.
 *
 * @param declared - The keys the schema declares.
 * @param value - The arguments as passed.
 * @returns {string[]} The undeclared keys.
 */
function undeclaredKeys(declared: readonly string[], value: unknown): string[] {
  if (typeof value !== "object" || value === null) return [];
  return Object.keys(value).filter((key) => !declared.includes(key));
}

/**
 * Formats one TypeBox failure; an enum failure names the allowed values.
 *
 * @param error - The failure.
 * @returns {string} One line.
 */
function failureLine(error: TLocalizedValidationError): string {
  const allowed = error.keyword === "enum" ? error.params.allowedValues : undefined;
  const message = Array.isArray(allowed) ? `must be one of ${allowed.join(", ")}` : error.message;
  return `Invalid arguments at ${error.instancePath || "/"}: ${message}`;
}

/**
 * Lists every TypeBox validation failure for an MCP client in one answer. An enum failure names
 * the allowed values and an undeclared key names itself, so the agent does not have to guess.
 *
 * @param schema - Schema used to validate the value.
 * @param value - Value that failed validation.
 * @returns {string[]} Human-readable validation failures, one per line.
 */
function validationErrors(schema: TSchema, value: unknown): string[] {
  const declared = Object.keys((schema as { properties?: object }).properties ?? {});
  const unknown = undeclaredKeys(declared, value);
  // A closed schema reports each undeclared key again, as `schema is false` at its path.
  const reported = new Set(
    unknown.map((key) => `/${key.replaceAll("~", "~0").replaceAll("/", "~1")}`),
  );
  const lines = [
    ...unknown.map(
      (key) =>
        `Invalid arguments: unknown property ${JSON.stringify(key)}; takes ${declared.join(", ")}`,
    ),
    ...Value.Errors(schema, value)
      .filter(
        (error) => error.keyword !== "additionalProperties" && !reported.has(error.instancePath),
      )
      .map(failureLine),
  ];
  return lines.length > 0 ? lines : ["Invalid arguments"];
}

/**
 * Wraps error text for the MCP client, replacing control bytes with spaces.
 *
 * Every error branch goes through here because parts of these messages echo client-controlled
 * values (a tool name, an argument): one raw newline or escape byte inside such a value would
 * forge extra lines that read as the server's own answer. Each line is cleaned on its own, so
 * only the breaks the server puts between validation failures survive.
 *
 * @param lines - Error lines to sanitize and return.
 * @returns {CallToolResult} MCP error result.
 */
function errorResult(...lines: readonly string[]): CallToolResult {
  const text = lines.map((line) => line.replaceAll(/[\p{Cc}\p{Zl}\p{Zp}]/gu, " ")).join("\n");
  return { content: [{ type: "text", text }], isError: true };
}

/**
 * Creates an unconnected MCP server exposing the hash tools.
 *
 * Built on the low-level `Server` even though the SDK marks it `@deprecated`, because
 * `McpServer.registerTool` accepts Standard Schema (Zod) only. TypeBox 1.x does not implement
 * Standard Schema, and these schemas are TypeBox, shared with the Pi extension; validating with
 * TypeBox also gives MCP the same error text Pi and OMP give.
 *
 * @returns {Server} Unconnected MCP server.
 */
export function createMcpServer(): Server {
  const toolsByName = new Map(tools.map((tool) => [tool.name as string, tool]));
  const server = new Server({ name: "hashes", version }, { capabilities: { tools: {} } });

  server.setRequestHandler(ListToolsRequestSchema, () => ({
    tools: tools.map((tool): Tool => ({
      name: tool.name,
      title: TOOL_TITLES[tool.name],
      description: TOOL_DESCRIPTIONS[tool.name],
      inputSchema: schemaOf(tool.name) as Tool["inputSchema"],
      // A KDF without a salt draws a new one each call, so computing is not idempotent.
      annotations: { ...annotations, idempotentHint: tool.name !== "hash_compute" },
    })),
  }));

  server.setRequestHandler(CallToolRequestSchema, (request) => {
    const tool = toolsByName.get(request.params.name);
    if (!tool) {
      return errorResult(`Unknown hashes tool: ${JSON.stringify(request.params.name)}`);
    }

    const args = request.params.arguments ?? {};
    const schema = schemaOf(tool.name);
    if (!Value.Check(schema, args)) {
      return errorResult(...validationErrors(schema, args));
    }

    try {
      const { content } = tool.execute(args);
      return { content };
    } catch (error) {
      return errorResult(
        `${tool.name} failed: ${error instanceof Error ? error.message : String(error)}`,
      );
    }
  });

  return server;
}
