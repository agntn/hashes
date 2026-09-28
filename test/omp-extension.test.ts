import { describe, expect, it, vi } from "vite-plus/test";
import type * as typebox from "@oh-my-pi/omptype/typebox";
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

import hashesExtension, {
  preview,
  sanitizeTerminalText,
} from "../packages/omp/extensions/hashes.ts";
import {
  hashAlgorithmsSchema,
  hashComputeSchema,
  hashHmacSchema,
  hashVerifySchema,
} from "../packages/shared/tool-schemas.ts";
import { Value } from "typebox/value";
import { TOOL_ARGUMENTS } from "../src/tool-operations.ts";
import {
  ompTestTheme as theme,
  ompToolContext,
  registerOmpExtension,
} from "./fixtures/omp-host.ts";

const CONTROL_BYTES = /[\u0000-\u001F\u007F-\u009F]/;

function registerTool(name: string): ToolDefinition {
  return registerOmpExtension(hashesExtension).tool(name);
}

function renderedText(component: unknown): string {
  return (component as { text: string }).text;
}

const sharedSchemas = {
  hash_compute: hashComputeSchema,
  hash_hmac: hashHmacSchema,
  hash_verify: hashVerifySchema,
  hash_algorithms: hashAlgorithmsSchema,
};

/** Arguments that probe each restated bound: the shared schema decides, OMP has to agree. */
const probes: Record<keyof typeof TOOL_ARGUMENTS, readonly unknown[]> = {
  hash_compute: [
    { algorithm: "sha256", input: "x" },
    { algorithm: "", input: "x" },
    { algorithm: "a".repeat(33), input: "x" },
    { algorithm: "sha256", input: "x", encoding: "base64url" },
    { algorithm: "sha256", input: "x", encoding: "binary" },
    { algorithm: "scrypt", input: "x", salt: "00ff" },
    { algorithm: "scrypt", input: "x", salt: "0" },
    { algorithm: "scrypt", input: "x", salt: "00".repeat(257) },
    { algorithm: "sha256", input: "x", saltHex: "00" },
    { algorithm: "xxhash", input: "x", parameters: { seed: 1 } },
    { algorithm: "scrypt", input: "x", parameters: { N: 1024, digest: "sha256" } },
    { algorithm: "xxhash", input: "x", parameters: { seed: 1.5 } },
    { algorithm: "xxhash", input: "x", parameters: { "1seed": 1 } },
    // No probe over MAX_PARAMETERS: omptype ignores maxProperties, so the shared executor enforces it.
    { algorithm: "sha256" },
  ],
  hash_hmac: [
    { algorithm: "sha256", input: "x", key: "" },
    { algorithm: "sha256", input: "x" },
    { algorithm: "sha256", input: "x", key: "k".repeat(10_001) },
    { algorithm: "sha256", input: "x", key: "k", salt: "00" },
  ],
  hash_verify: [
    { algorithm: "sha256", input: "x", expected: "ab" },
    { algorithm: "sha256", input: "x", expected: "" },
    { algorithm: "sha256", input: "x", expected: "a".repeat(1025) },
    { algorithm: "sha256", input: "x", expected: "ab", encoding: "base64" },
    {
      algorithm: "pbkdf2",
      input: "x",
      expected: "ab",
      salt: "00",
      parameters: { iterations: 1000 },
    },
    { algorithm: "pbkdf2", input: "x", expected: "ab", parameters: { iterations: "x".repeat(65) } },
  ],
  hash_algorithms: [
    {},
    { family: "password" },
    { family: "toString" },
    { algorithm: "" },
    { limit: 1 },
  ],
};

describe("sanitizeTerminalText", () => {
  it("strips ANSI, OSC, C0, and C1 sequences", () => {
    const clean = sanitizeTerminalText(
      "\u001B]0;evil\u0007safe\u001B[31mname\u009B1mtail\u0000end",
    );

    expect(clean).not.toMatch(CONTROL_BYTES);
    expect(clean).not.toContain("evil");
    expect(clean).toContain("safe");
  });

  it("cuts a long preview", () => {
    expect(preview("x".repeat(100))).toBe(`${"x".repeat(39)}…`);
    expect(preview(42)).toBe("42");
  });
});

describe("omp hashes extension", () => {
  it("registers the four hash tools as read-approval tools", () => {
    const host = registerOmpExtension(hashesExtension);

    expect([...host.tools.keys()]).toEqual(Object.keys(TOOL_ARGUMENTS));
    expect(host.labels).toEqual(["Hashes"]);
    for (const tool of host.tools.values()) expect(tool.approval).toBe("read");
  });

  it.each(Object.entries(probes))(
    "keeps the restated %s schema with the shared one",
    (name, values) => {
      const tool = registerTool(name);
      const accepts = (value: unknown): boolean =>
        (tool.parameters as unknown as typebox.TSchema).safeParse(value).success;
      const shared = sharedSchemas[name as keyof typeof sharedSchemas];

      expect(values.some((value) => Value.Check(shared, value))).toBe(true);
      expect(values.some((value) => !Value.Check(shared, value))).toBe(true);
      for (const value of values) {
        expect([JSON.stringify(value).slice(0, 60), accepts(value)]).toEqual([
          JSON.stringify(value).slice(0, 60),
          Value.Check(shared, value),
        ]);
      }
    },
  );

  it("executes against the library and returns structured details", async () => {
    const result = await registerTool("hash_verify").execute(
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

  it("keeps the HMAC key off the status line and sanitizes the input", () => {
    const text = renderedText(
      registerTool("hash_hmac").renderCall?.(
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
    (isPartial, spinnerFrame, icon) => {
      const text = renderedText(
        registerTool("hash_algorithms").renderCall?.(
          { family: "password" },
          { expanded: false, isPartial, spinnerFrame },
          theme,
        ),
      );

      expect(text).toBe(`${icon} accent(Hash Algorithms): muted(password)`);
    },
  );

  it("summarizes a digest, a verdict and a listing, and nothing for an error", () => {
    const digest = renderedText(
      registerTool("hash_compute").renderResult?.(
        { content: [], details: { algorithm: "sha256", digest: "ab\u001B[31mcd" } },
        { expanded: false, isPartial: false },
        theme,
      ),
    );
    const verdict = renderedText(
      registerTool("hash_verify").renderResult?.(
        { content: [], details: { match: false } },
        { expanded: false, isPartial: false },
        theme,
      ),
    );
    const failed = renderedText(
      registerTool("hash_algorithms").renderResult?.(
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
