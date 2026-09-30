import { describe, expect, it, vi } from "vite-plus/test";

// OMP swaps `typebox` for its shim, whose objects have no `.properties` (#58).
vi.mock("typebox", () => import("@oh-my-pi/omptype/typebox"));
vi.mock("@oh-my-pi/pi-coding-agent", () => ({ Text: class {} }));

import hashesExtension from "../packages/omp/extensions/hashes.ts";
import { ompToolContext, registerOmpExtension } from "./fixtures/omp-host.ts";

describe("omp hashes extension under the host TypeBox shim", () => {
  it.each([
    ["hash_compute", { algorithm: "sha256", input: "abc" }, /^ba7816bf/],
    ["hash_hmac", { algorithm: "sha256", input: "abc", key: "k" }, /^[0-9a-f]{64}/],
    [
      "hash_verify",
      { algorithm: "md5", input: "hello", expected: "5d41402abc4b2a76b9719d911017c592" },
      /^MATCH/,
    ],
    ["hash_algorithms", { family: "SHA" }, /sha256/],
  ] as const)("runs %s", async (name, params, answer) => {
    const tool = registerOmpExtension(hashesExtension).tool(name);
    const result = await tool.execute("call-1", params, undefined, undefined, ompToolContext);

    const [part] = result.content;
    expect(part?.type === "text" ? part.text : "").toMatch(answer);
  });

  it("still rejects an argument the tool does not take", async () => {
    const tool = registerOmpExtension(hashesExtension).tool("hash_compute");

    await expect(
      tool.execute(
        "call-1",
        { algorithm: "sha256", input: "abc", saltHex: "00" },
        undefined,
        undefined,
        ompToolContext,
      ),
    ).rejects.toThrow(/takes only algorithm, input, inputEncoding, encoding, salt, parameters/);
  });
});
