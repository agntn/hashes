import { describe, expect, it, vi } from "vite-plus/test";
import type { ToolDefinition } from "@oh-my-pi/pi-coding-agent";

// Compiled OMP injects only the package root into extensions, so the renderers run
// against a capturing Text and the TUI barrel must stay off the load path.
vi.mock("@oh-my-pi/pi-coding-agent", () => ({
  Text: class {
    readonly text: string;

    constructor(text: string) {
      this.text = text;
    }
  },
}));
vi.mock("@oh-my-pi/pi-coding-agent/tui", () => {
  throw new Error("The OMP host does not inject the TUI barrel");
});

import hashesExtension, { preview } from "../packages/omp/extensions/hashes.ts";
import {
  hashAlgorithmsSchema,
  hashDigestExtendSchema,
  hashDigestIdentifySchema,
  hashComputeSchema,
  hashHmacSchema,
  hashVerifySchema,
} from "../packages/shared/tool-schemas.ts";
import { Value } from "typebox/value";
import { ToolInputError } from "@agntn/tools";
import { TOOL_ARGUMENTS } from "../src/tool-operations.ts";
import {
  ompTestTheme as theme,
  ompToolContext,
  registerOmpExtension,
} from "./fixtures/omp-host.ts";

const CONTROL_BYTES = /[\u0000-\u001F\u007F-\u009F]/;

async function registerTool(name: string): Promise<ToolDefinition> {
  return (await registerOmpExtension(hashesExtension)).tool(name);
}

function renderedText(component: unknown): string {
  return (component as { text: string }).text;
}

const sharedSchemas = {
  hashes_compute: hashComputeSchema,
  hashes_hmac_compute: hashHmacSchema,
  hashes_verify: hashVerifySchema,
  hashes_digest_extend: hashDigestExtendSchema,
  hashes_digest_identify: hashDigestIdentifySchema,
  hashes_algorithms: hashAlgorithmsSchema,
};

/** Arguments that probe each bound: the shared schema decides, a call through OMP has to agree. */
const probes: Record<keyof typeof TOOL_ARGUMENTS, readonly unknown[]> = {
  hashes_compute: [
    { algorithm: "sha256", input: "x" },
    { algorithm: "", input: "x" },
    { algorithm: "a".repeat(33), input: "x" },
    { algorithm: "sha256", input: "x", encoding: "base64url" },
    { algorithm: "sha256", input: "x", encoding: "binary" },
    { algorithm: "sha256", input: "00", inputEncoding: "hex" },
    { algorithm: "sha256", input: "AA==", inputEncoding: "base64" },
    { algorithm: "sha256", input: "x", inputEncoding: "latin1" },
    { algorithm: "scrypt", input: "x", salt: "00ff" },
    { algorithm: "scrypt", input: "x", salt: "0" },
    { algorithm: "scrypt", input: "x", salt: "00".repeat(257) },
    { algorithm: "sha256", input: "x", saltHex: "00" },
    { algorithm: "xxhash", input: "x", parameters: { seed: 1 } },
    { algorithm: "scrypt", input: "x", parameters: { N: 1024, digest: "sha256" } },
    { algorithm: "xxhash", input: "x", parameters: { seed: 1.5 } },
    { algorithm: "xxhash", input: "x", parameters: { "1seed": 1 } },
    {
      algorithm: "xxhash",
      input: "x",
      parameters: { a: 1, b: 1, c: 1, d: 1, e: 1, f: 1, g: 1, h: 1, i: 1 },
    },
    { algorithm: "sha256" },
  ],
  hashes_hmac_compute: [
    { algorithm: "sha256", input: "x", key: "" },
    { algorithm: "sha256", input: "x" },
    { algorithm: "sha256", input: "x", key: "k".repeat(10_001) },
    { algorithm: "sha256", input: "x", key: "k", salt: "00" },
    { algorithm: "sha256", input: "00", key: "k", inputEncoding: "hex" },
    { algorithm: "sha256", input: "00", key: "k", inputEncoding: "binary" },
    { algorithm: "sha256", input: "x", key: "aa", keyEncoding: "hex" },
    { algorithm: "sha256", input: "x", key: "aa", keyEncoding: "base64url" },
  ],
  hashes_digest_extend: [
    { algorithm: "sha256", digest: "00".repeat(32), message: "m", suffix: "s", secretLength: 6 },
    { algorithm: "sha256", digest: "0".repeat(63), message: "m", suffix: "s", secretLength: 6 },
    { algorithm: "sha256", digest: "00".repeat(65), message: "m", suffix: "s", secretLength: 6 },
    { algorithm: "sha256", digest: "00".repeat(32), message: "m", suffix: "s", secretLength: -1 },
    { algorithm: "sha256", digest: "00".repeat(32), message: "m", suffix: "s", secretLength: 1.5 },
    {
      algorithm: "sha256",
      digest: "00".repeat(32),
      message: "m",
      suffix: "s",
      secretLength: 1_000_001,
    },
    {
      algorithm: "sha256",
      digest: "00".repeat(32),
      message: "6d",
      messageEncoding: "hex",
      suffix: "cw==",
      suffixEncoding: "base64",
      secretLength: 1,
      secretLengthMax: 8,
    },
    {
      algorithm: "sha256",
      digest: "00".repeat(32),
      message: "m",
      suffix: "s",
      suffixEncoding: "latin1",
      secretLength: 1,
    },
    { algorithm: "sha256", digest: "00".repeat(32), message: "m", secretLength: 1 },
  ],
  hashes_digest_identify: [
    { digest: "00".repeat(16) },
    { digest: "$2b$05$x" },
    { digest: "" },
    { digest: "a".repeat(1_025) },
    { digest: 16 },
    {},
  ],
  hashes_verify: [
    { algorithm: "sha256", input: "x", expected: "ab" },
    { algorithm: "sha256", input: "x", expected: "" },
    { algorithm: "sha256", input: "x", expected: "a".repeat(1025) },
    { algorithm: "sha256", input: "x", expected: "ab", encoding: "base64" },
    { algorithm: "sha256", input: "00", expected: "ab", inputEncoding: "hex" },
    { algorithm: "sha256", input: "00", expected: "ab", inputEncoding: "base64url" },
    {
      algorithm: "pbkdf2",
      input: "x",
      expected: "ab",
      salt: "00",
      parameters: { iterations: 1000 },
    },
    { algorithm: "pbkdf2", input: "x", expected: "ab", parameters: { iterations: "x".repeat(65) } },
  ],
  hashes_algorithms: [
    {},
    { category: "password" },
    { category: "toString" },
    { family: "SHA" },
    { family: "" },
    { family: "S".repeat(33) },
    { algorithm: "" },
    { limit: 1 },
  ],
};

describe("preview", () => {
  it("strips ANSI, OSC, C0, and C1 sequences", () => {
    const clean = preview("\u001B]0;evil\u0007safe\u001B[31mname\u009B1mtail\u0000end");

    expect(clean).not.toMatch(CONTROL_BYTES);
    expect(clean).not.toContain("evil");
    expect(clean).toContain("safe");
  });

  it("turns the Unicode line and paragraph separators into spaces", () => {
    expect(preview("a\u2028b\u2029c")).toBe("a b c");
  });

  it("cuts a long preview", () => {
    expect(preview("x".repeat(100))).toBe(`${"x".repeat(39)}…`);
    expect(preview(42)).toBe("42");
  });
});

describe("omp hashes extension", () => {
  it("registers the four hash tools with read approval", async () => {
    const host = await registerOmpExtension(hashesExtension);

    expect([...host.tools.keys()]).toEqual(Object.keys(TOOL_ARGUMENTS));
    expect(host.labels).toEqual(["Hashes"]);
    for (const tool of host.tools.values()) expect(tool.approval).toBe("read");
  });

  it.each(Object.entries(probes))("checks %s against the shared schema", async (name, values) => {
    const tool = await registerTool(name);
    const shared = sharedSchemas[name as keyof typeof sharedSchemas];
    const outcome = async (value: unknown): Promise<string> =>
      Promise.resolve(tool.execute("call-1", value, undefined, undefined, ompToolContext)).then(
        () => "ran",
        (error: unknown) => (error instanceof ToolInputError ? "refused" : "ran"),
      );

    expect(tool.parameters).toEqual(shared);
    expect(values.some((value) => Value.Check(shared, value))).toBe(true);
    expect(values.some((value) => !Value.Check(shared, value))).toBe(true);
    for (const value of values) {
      expect([JSON.stringify(value).slice(0, 60), await outcome(value)]).toEqual([
        JSON.stringify(value).slice(0, 60),
        Value.Check(shared, value) ? "ran" : "refused",
      ]);
    }
  });

  it("executes against the library and returns structured details", async () => {
    const result = await (
      await registerTool("hashes_verify")
    ).execute(
      "call-1",
      { algorithm: "md5", input: "hello", expected: "5D41402ABC4B2A76B9719D911017C592" },
      undefined,
      undefined,
      ompToolContext,
    );

    const [part] = result.content;
    expect(part?.type === "text" ? part.text : "").toMatch(/^MATCH/);
    expect(result.details).toMatchObject({ match: true, algorithm: "md5" });
  });

  it("keeps the HMAC key off the status line and sanitizes the input", async () => {
    const text = renderedText(
      (await registerTool("hashes_hmac_compute")).renderCall?.(
        { algorithm: "sha256", input: "\u001B]0;evil\u0007msg\nnext", key: "hunter2" },
        { expanded: false, isPartial: false },
        theme,
      ),
    );

    expect(text).not.toMatch(CONTROL_BYTES);
    expect(text).not.toContain("hunter2");
    expect(text).toBe("success:status.done accent(Hash HMAC): muted(sha256 msg next)");
  });

  it.each([
    [false, undefined, "success:status.done"],
    [true, undefined, "muted:status.pending"],
    [true, 3, "frame-1"],
  ] as const)(
    "draws the call status with the host theme (partial=%s, frame=%s)",
    async (isPartial, spinnerFrame, icon) => {
      const text = renderedText(
        (await registerTool("hashes_algorithms")).renderCall?.(
          { category: "password" },
          { expanded: false, isPartial, spinnerFrame },
          theme,
        ),
      );

      expect(text).toBe(`${icon} accent(Hash Algorithms): muted(password)`);
    },
  );

  it("summarizes a digest, a verdict and a listing, and nothing for an error", async () => {
    const digest = renderedText(
      (await registerTool("hashes_compute")).renderResult?.(
        { content: [], details: { algorithm: "sha256", digest: "ab\u001B[31mcd" } },
        { expanded: false, isPartial: false },
        theme,
      ),
    );
    const verdict = renderedText(
      (await registerTool("hashes_verify")).renderResult?.(
        { content: [], details: { match: false } },
        { expanded: false, isPartial: false },
        theme,
      ),
    );
    const failed = renderedText(
      (await registerTool("hashes_algorithms")).renderResult?.(
        { content: [], details: { algorithms: [1, 2] }, isError: true },
        { expanded: false, isPartial: false },
        theme,
      ),
    );

    expect(digest).toBe("success:status.done accent(Hash Compute) accent([read]) dim(sha256 abcd)");
    expect(verdict).toBe("success:status.done accent(Hash Verify) accent([read]) dim(mismatch)");
    expect(failed).toBe("error:status.error accent(Hash Algorithms) accent([read])");
  });
});
