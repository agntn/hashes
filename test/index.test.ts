import { createHash, createHmac, pbkdf2Sync, scryptSync } from "node:crypto";
import { readdirSync } from "node:fs";
import { crc32 as zlibCrc32 } from "node:zlib";
import { describe, expect, it } from "vite-plus/test";
import { builtins } from "../src/algorithms/index.ts";
import {
  DependencyError,
  HashError,
  InvalidOptionError,
  MissingOptionError,
  UnknownAlgorithmError,
  algorithms,
  builtinAlgorithms,
  create,
  digestMatches,
  has,
  hashFamilies,
  normalizeError,
  register,
  resolveAlgorithm,
  version,
  type Pbkdf2Options,
  type ScryptOptions,
  type XxhashOptions,
} from "../src/index.ts";
import pkg from "../package.json" with { type: "json" };

/** Algorithms Node's OpenSSL computes too, under its own name. */
const OPENSSL_NAMES = {
  sha256: "sha256",
  sha384: "sha384",
  sha512: "sha512",
  "sha3-256": "sha3-256",
  "sha3-512": "sha3-512",
  blake2b: "blake2b512",
  blake2s: "blake2s256",
  ripemd160: "ripemd160",
  md5: "md5",
  sha1: "sha1",
} as const;

const SAMPLES = ["", "abc", "hello world", "zażółć gęślą jaźń 🦊"];

describe("@agntn/hashes", () => {
  it("exports the package version", () => {
    expect(version).toBe(pkg.version);
  });
});

describe("registry", () => {
  it("seeds every built-in in listing order", () => {
    expect(algorithms().slice(0, builtinAlgorithms.length)).toEqual([...builtinAlgorithms]);
  });

  it("keeps the builtins list, the names list and the algorithm files in step", () => {
    const files = readdirSync(new URL("../src/algorithms/", import.meta.url))
      .filter((file) => file !== "index.ts")
      .map((file) => file.replace(/\.ts$/, ""))
      .toSorted();

    expect(builtins.map((entry) => entry.name)).toEqual([...builtinAlgorithms]);
    expect([...builtinAlgorithms].toSorted()).toEqual(files);
  });

  it("names every algorithm the way its info does", () => {
    for (const name of builtinAlgorithms) {
      const algorithm = create(name);
      expect(algorithm.name()).toBe(name);
      expect(algorithm.info().name).toBe(name);
      expect(hashFamilies).toContain(algorithm.info().family);
    }
  });

  it("answers has() for registered names only", () => {
    expect(has("sha256")).toBe(true);
    expect(has("nonexistent")).toBe(false);
    expect(has("toString")).toBe(false);
  });

  it("registers an algorithm from outside the package", () => {
    const sha256 = create("sha256");
    register("sha256-twice", () => ({
      name: () => "sha256-twice",
      info: () => ({ ...sha256.info(), name: "sha256-twice" }),
      hash: (input, options) => sha256.hash(String(sha256.hash(input).digest), options),
    }));

    expect(has("sha256-twice")).toBe(true);
    expect(algorithms().at(-1)).toBe("sha256-twice");
    expect(resolveAlgorithm("SHA256_TWICE").hash("abc").digest).toBe(
      createHash("sha256").update(createHash("sha256").update("abc").digest("hex")).digest("hex"),
    );
  });

  it("resolves typed names: case, spaces and underscores", () => {
    expect(resolveAlgorithm("SHA256").name()).toBe("sha256");
    expect(resolveAlgorithm(" sha3_256 ").name()).toBe("sha3-256");
    expect(resolveAlgorithm("SHA3 512").name()).toBe("sha3-512");
  });

  it("throws UnknownAlgorithmError with the registered names", () => {
    expect(() => resolveAlgorithm("nonexistent")).toThrow(UnknownAlgorithmError);
    expect(() => resolveAlgorithm("nonexistent")).toThrow(/Available: sha256, sha384/);
    expect(() => create("constructor")).toThrow(UnknownAlgorithmError);
    expect(() => resolveAlgorithm()).toThrow("Unknown algorithm: (none)");
  });
});

describe("digests", () => {
  it.each(Object.entries(OPENSSL_NAMES))("%s matches OpenSSL", (name, openssl) => {
    for (const sample of SAMPLES) {
      const result = create(name).hash(sample);
      expect(result.digest).toBe(createHash(openssl).update(sample).digest("hex"));
      expect(result.digestLength).toBe(create(name).info().digestLength);
      expect(result).toMatchObject({ algorithm: name, operation: "hash", encoding: "hex" });
    }
  });

  it.each(Object.entries(OPENSSL_NAMES).filter(([name]) => create(name).info().hmac))(
    "HMAC-%s matches OpenSSL",
    (name, openssl) => {
      const result = create(name).hash("message", { key: "secret" });
      expect(result.digest).toBe(createHmac(openssl, "secret").update("message").digest("hex"));
      expect(result.operation).toBe("hmac");
    },
  );

  it("takes an empty HMAC key as a key, not as no key", () => {
    expect(create("sha256").hash("message", { key: "" }).digest).toBe(
      createHmac("sha256", "").update("message").digest("hex"),
    );
  });

  it("refuses HMAC where the algorithm has none", () => {
    expect(() => create("blake3").hash("message", { key: "secret" })).toThrow(HashError);
  });

  it("matches the published BLAKE3 vectors", () => {
    expect(create("blake3").hash("").digest).toBe(
      "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262",
    );
    expect(create("blake3").hash("abc").digest).toBe(
      "6437b3ac38465133ffb63b75273a8db548c558465d79db03fd359c6cd5bd9d85",
    );
  });

  it("matches the published CRC-32 check value", () => {
    expect(create("crc32").hash("123456789").digest).toBe("cbf43926");
    expect(create("crc32").hash("").digest).toBe("00000000");
  });

  it("matches zlib for CRC-32", () => {
    for (const sample of SAMPLES) {
      expect(create("crc32").hash(sample).digest).toBe(
        zlibCrc32(sample).toString(16).padStart(8, "0"),
      );
    }
  });

  it("matches the published XXH64 vectors, with a seed", () => {
    expect(create("xxhash").hash("").digest).toBe("ef46db3751d8e999");
    expect(create("xxhash").hash("abc").digest).toBe("44bc2cf5ad770999");
    const long = "Nobody inspects the spammish repetition";
    expect(create("xxhash").hash(long).digest).toBe("fbcea83c8a378bf1");
    const seeded = create("xxhash").hash("abc", { seed: 1 } as XxhashOptions);
    expect(seeded.digest).not.toBe("44bc2cf5ad770999");
    expect(seeded.options).toMatchObject({ seed: 1 });
    expect(() => create("xxhash").hash("abc", { seed: -1 } as XxhashOptions)).toThrow(
      InvalidOptionError,
    );
  });

  it("matches the published FNV-1a 64 vectors", () => {
    expect(create("fnv1a").hash("").digest).toBe("cbf29ce484222325");
    expect(create("fnv1a").hash("a").digest).toBe("af63dc4c8601ec8c");
    expect(create("fnv1a").hash("foobar").digest).toBe("85944171f73967e8");
  });

  it("hashes bytes as they are", () => {
    const bytes = new Uint8Array([0, 255, 1, 128]);
    expect(create("sha256").hash(bytes).digest).toBe(
      createHash("sha256").update(bytes).digest("hex"),
    );
  });

  it("encodes as hex, base64, unpadded base64url and raw bytes", () => {
    const raw = createHash("sha256").update("test").digest();
    const sha256 = create("sha256");

    expect(sha256.hash("test", { encoding: "base64" }).digest).toBe(raw.toString("base64"));
    expect(sha256.hash("test", { encoding: "base64url" }).digest).toBe(raw.toString("base64url"));
    expect(sha256.hash("test", { encoding: "base64url" }).digest).not.toMatch(/[=+/]/);
    expect(sha256.hash("test", { encoding: "binary" }).digest).toEqual(new Uint8Array(raw));
    expect(create("crc32").hash("test", { encoding: "binary" }).digest).toEqual(
      new Uint8Array(Buffer.from(zlibCrc32("test").toString(16).padStart(8, "0"), "hex")),
    );
  });
});

describe("key derivation", () => {
  const salt = "deadbeef00000000deadbeef00000000";

  it("matches Node's scrypt and reports the salt and cost", () => {
    const result = create("scrypt").hash("password", {
      salt,
      N: 1024,
      keyLength: 32,
    } as ScryptOptions);
    expect(result.digest).toBe(
      scryptSync("password", Buffer.from(salt, "hex"), 32, { N: 1024, r: 8, p: 1 }).toString("hex"),
    );
    expect(result.options).toMatchObject({ salt, N: 1024, r: 8, p: 1, keyLength: 32 });
  });

  it("matches Node's PBKDF2 for every digest it offers", () => {
    for (const [digest, openssl] of [
      ["sha256", "sha256"],
      ["sha512", "sha512"],
      ["sha3-256", "sha3-256"],
    ] as const) {
      const result = create("pbkdf2").hash("password", {
        salt,
        iterations: 1000,
        digest,
      } as Pbkdf2Options);
      expect(result.digest).toBe(
        pbkdf2Sync("password", Buffer.from(salt, "hex"), 1000, 64, openssl).toString("hex"),
      );
    }
  });

  it("draws a fresh 32-byte salt when none is given and names it", () => {
    const first = create("scrypt").hash("password", { N: 1024 } as ScryptOptions);
    const second = create("scrypt").hash("password", { N: 1024 } as ScryptOptions);
    expect(first.options["salt"]).toMatch(/^[0-9a-f]{64}$/);
    expect(first.options["salt"]).not.toBe(second.options["salt"]);
  });

  it("rejects a digest name inherited from Object.prototype", () => {
    expect(() =>
      create("pbkdf2").hash("x", { salt, digest: "constructor" } as Pbkdf2Options),
    ).toThrow(/Invalid option digest=constructor/);
  });

  it("rejects bad cost parameters", () => {
    expect(() => create("scrypt").hash("x", { salt, N: 1000 } as ScryptOptions)).toThrow(
      InvalidOptionError,
    );
    expect(() => create("pbkdf2").hash("x", { salt, iterations: 0 } as Pbkdf2Options)).toThrow(
      InvalidOptionError,
    );
  });
});

describe("digestMatches", () => {
  const sha256 = create("sha256");

  it("ignores case in hex only", () => {
    const hex = sha256.hash("abc");
    expect(digestMatches(hex, String(hex.digest).toUpperCase())).toBe(true);
    expect(digestMatches(hex, ` ${String(hex.digest)}\n`)).toBe(true);

    const base64 = sha256.hash("abc", { encoding: "base64" });
    expect(digestMatches(base64, String(base64.digest))).toBe(true);
    // Lowercasing base64 changes the bytes it names; the old comparison called this a match.
    expect(digestMatches(base64, String(base64.digest).toLowerCase())).toBe(false);
  });

  it("rejects a digest that is not valid in the encoding or has another length", () => {
    const hex = sha256.hash("abc");
    expect(digestMatches(hex, "zz")).toBe(false);
    expect(digestMatches(hex, String(hex.digest).slice(0, 62))).toBe(false);
    expect(digestMatches(sha256.hash("abc", { encoding: "base64url" }), "+/")).toBe(false);
  });

  it("refuses a binary result", () => {
    expect(() => digestMatches(sha256.hash("abc", { encoding: "binary" }), "00")).toThrow(
      InvalidOptionError,
    );
  });
});

describe("errors", () => {
  it("keeps one hierarchy under HashError", () => {
    for (const error of [
      new UnknownAlgorithmError("fnv99", ["fnv1a"]),
      new InvalidOptionError("encoding", "junk", "unknown format"),
      new MissingOptionError("key"),
      new DependencyError("blake3", "@noble/hashes"),
    ]) {
      expect(error).toBeInstanceOf(HashError);
      expect(error.name).toBe(error.constructor.name);
    }
  });

  it("carries its fields and names them in the message", () => {
    const unknown = new UnknownAlgorithmError("fnv99", ["fnv1a"]);
    expect(unknown).toMatchObject({ algorithm: "fnv99", available: ["fnv1a"] });
    expect(unknown.message).toBe("Unknown algorithm: fnv99. Available: fnv1a");

    const invalid = new InvalidOptionError("encoding", "junk", "unknown format");
    expect(invalid).toMatchObject({ option: "encoding", value: "junk", reason: "unknown format" });
    expect(invalid.message).toContain("encoding=junk");

    expect(new MissingOptionError("key").option).toBe("key");
    expect(new DependencyError("blake3", "@noble/hashes").message).toContain("@noble/hashes");
  });

  it("normalizes foreign errors", () => {
    const own = new UnknownAlgorithmError("foo");
    expect(normalizeError(own)).toBe(own);
    expect(normalizeError(new Error("disk full")).message).toBe("disk full");
    expect(normalizeError("oops")).toBeInstanceOf(HashError);
    expect(normalizeError(new Error("bad input"), "fnv1a").message).toBe("[fnv1a] bad input");
  });
});
