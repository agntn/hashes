import { createHash, createHmac } from "node:crypto";
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

  it("keys an HMAC with the bytes a hex key spells", async () => {
    const output = await hashTools.hash_hmac.execute?.(
      { algorithm: "sha256", input: "m", key: "aaff", keyEncoding: "hex" },
      options,
    );

    expect(output).toMatchObject({
      digest: createHmac("sha256", Buffer.from([0xaa, 0xff]))
        .update("m")
        .digest("hex"),
    });
  });

  it("hashes the bytes a hex input spells", async () => {
    const output = await hashTools.hash_compute.execute?.(
      { algorithm: "sha256", input: "00ff", inputEncoding: "hex" },
      options,
    );

    expect(output).toMatchObject({
      digest: createHash("sha256")
        .update(Buffer.from([0, 255]))
        .digest("hex"),
    });
  });

  it("rejects an undeclared key before the executor runs", async () => {
    const schema = asSchema(hashTools.hash_compute.inputSchema);
    const result = await schema.validate?.({ algorithm: "sha256", input: "x", saltHex: "00" });

    expect(result?.success).toBe(false);
  });
});
