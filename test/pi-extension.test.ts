import { createHash } from "node:crypto";
import { fileURLToPath } from "node:url";

import { Value } from "typebox/value";
import { describe, expect, it } from "vite-plus/test";

import { MAX_ALGORITHM_LENGTH, TOOL_ARGUMENTS } from "../src/tool-operations.ts";
import { loadPiExtension } from "./fixtures/pi-host.ts";

const extensionPath = fileURLToPath(
  new URL("../packages/pi/extensions/hashes.ts", import.meta.url),
);

describe("pi hashes extension", () => {
  it("registers the four hash tools and nothing else", async () => {
    const host = await loadPiExtension(extensionPath);

    expect([...host.tools.keys()]).toEqual(Object.keys(TOOL_ARGUMENTS));
  });

  it("validates with the shared closed schemas", async () => {
    const tool = (await loadPiExtension(extensionPath)).tool("hash_compute");
    const accepts = (value: unknown): boolean => Value.Check(tool.parameters, value);

    expect(accepts({ algorithm: "sha256", input: "x" })).toBe(true);
    expect(accepts({ algorithm: "a".repeat(MAX_ALGORITHM_LENGTH + 1), input: "x" })).toBe(false);
    expect(accepts({ algorithm: "sha256", input: "x", encoding: "binary" })).toBe(false);
    expect(accepts({ algorithm: "sha256", input: "x", saltHex: "00" })).toBe(false);
  });

  it("executes through the shared executor and returns structured details", async () => {
    const host = await loadPiExtension(extensionPath);

    const result = await host
      .tool("hash_compute")
      .execute("call-1", { algorithm: "sha256", input: "abc" }, undefined, undefined, host.context);

    const digest = createHash("sha256").update("abc").digest("hex");
    expect(result.content[0]).toEqual({ type: "text", text: `${digest}\nsha256, hex, 32 bytes` });
    expect(result.details).toMatchObject({ algorithm: "sha256", digest, digestLength: 32 });
  });

  it("throws the executor's error for the host to report", async () => {
    const host = await loadPiExtension(extensionPath);

    await expect(
      host
        .tool("hash_hmac")
        .execute(
          "call-2",
          { algorithm: "blake3", input: "m", key: "k" },
          undefined,
          undefined,
          host.context,
        ),
    ).rejects.toThrow("has no HMAC mode");
  });
});
