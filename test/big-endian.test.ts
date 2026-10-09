import { argon2Sync, createHash } from "node:crypto";
import { describe, expect, it, vi } from "vite-plus/test";

/** A `Uint32Array` that stores `[1]` with its low byte last, the way s390x does. */
class BigEndianProbe extends Uint32Array {
  constructor(source: number | readonly number[]) {
    if (typeof source !== "number" && source.length === 1 && source[0] === 1) {
      super(1);
      new Uint8Array(this.buffer)[3] = 1;
    } else if (typeof source === "number") {
      super(source);
    } else {
      super(source);
    }
  }
}

vi.stubGlobal("Uint32Array", BigEndianProbe);
const { blake2b } = await import("../src/core/blake2b.ts");
const { argon2id } = await import("../src/core/argon2.ts");
vi.unstubAllGlobals();

describe("on a platform that reports big-endian", () => {
  it("BLAKE2b reads its blocks byte by byte and still matches Node", () => {
    for (const length of [0, 3, 127, 128, 129, 300]) {
      const data = Uint8Array.from({ length }, (_, i) => i);
      expect(blake2b(data, 64).toHex()).toBe(createHash("blake2b512").update(data).digest("hex"));
    }
  });

  it("BLAKE2b personalizes like Python's hashlib", () => {
    /** Python hashlib.blake2b(bytes(range(200)), digest_size=38, person=b"ZcashPoW"). */
    const data = Uint8Array.from({ length: 200 }, (_, i) => i);
    expect(blake2b(data, 38, new TextEncoder().encode("ZcashPoW")).toHex()).toBe(
      "de9a31a73652820f2eae61766383ecef002e53307324026506e915b4e04e126eb37644232e53",
    );
  });

  it("Argon2id matches Node over two lanes and a long tag", () => {
    const message = new Uint8Array(3);
    const nonce = new Uint8Array(16).fill(2);
    const options = { memory: 64, iterations: 2, parallelism: 2, keyLength: 72 };
    const expected = argon2Sync("argon2id", {
      message,
      nonce,
      memory: 64,
      passes: 2,
      parallelism: 2,
      tagLength: 72,
    });
    expect(argon2id(message, nonce, options).toHex()).toBe(expected.toString("hex"));
  });
});
