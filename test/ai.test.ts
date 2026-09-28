import { createHash } from "node:crypto";
import { asSchema } from "ai";
import { describe, expect, it } from "vite-plus/test";
import { hashTools } from "../src/ai.ts";
import { TOOL_ARGUMENTS } from "../src/tool-operations.ts";

const options = { toolCallId: "call-1", messages: [], context: undefined };

describe("AI SDK tools", () => {
  it("covers every tool MCP, Pi and OMP offer", () => {
    expect(Object.keys(hashTools)).toEqual(Object.keys(TOOL_ARGUMENTS));
  });

  it("runs the shared executor and returns its details with the text", async () => {
    const output = await hashTools.hash_compute.execute?.(
      { algorithm: "sha256", input: "abc" },
      options,
    );
    const digest = createHash("sha256").update("abc").digest("hex");

    expect(output).toMatchObject({
      algorithm: "sha256",
      digest,
      text: `${digest}\nsha256, hex, 32 bytes`,
    });
  });

  it("rejects an undeclared key before the executor runs", async () => {
    const schema = asSchema(hashTools.hash_compute.inputSchema);
    const result = await schema.validate?.({ algorithm: "sha256", input: "x", saltHex: "00" });

    expect(result?.success).toBe(false);
  });
});
