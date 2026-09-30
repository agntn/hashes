import { execFileSync } from "node:child_process";
import { createHash, createHmac, hkdfSync, pbkdf2Sync, scryptSync } from "node:crypto";
import { readdirSync } from "node:fs";
import { crc32 as zlibCrc32 } from "node:zlib";
import { describe, expect, it } from "vite-plus/test";
import { Md5, Sha1, builtins } from "../src/algorithms/index.ts";
import { algorithmInfos } from "../src/core/resolve.ts";
import {
  type AlgorithmInfo,
  DependencyError,
  Hash,
  HashError,
  FixedHash,
  InvalidOptionError,
  MissingOptionError,
  UnknownAlgorithmError,
  Blake2bHasher,
  Ripemd160Hasher,
  Sha256Hasher,
  Sha512Hasher,
  algorithms,
  blake256,
  blake2b,
  builtinAlgorithms,
  crc16Xmodem,
  crc32,
  create,
  digestMatches,
  has,
  hash160,
  hash256,
  hashCategories,
  hkdf,
  hkdfExpand,
  hkdfExtract,
  hmac,
  keccak256,
  md5,
  normalizeError,
  pbkdf2,
  register,
  resolveAlgorithm,
  ripemd160,
  sha1,
  sha256,
  sha3_256,
  sha512,
  version,
  type HashOptions,
  type HkdfOptions,
  type Pbkdf2Options,
  type ScryptOptions,
  type XxhashOptions,
} from "../src/index.ts";
import * as root from "../src/index.ts";
import buildConfig from "../build.config.ts";
import pkg from "../package.json" with { type: "json" };

/** Algorithms Node's OpenSSL computes too, under its own name. */
const OPENSSL_NAMES = {
  sha256: "sha256",
  sha384: "sha384",
  sha512: "sha512",
  "sha3-256": "sha3-256",
  "sha3-512": "sha3-512",
  keccak256: "keccak-256",
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

    expect(builtins.map((HashClass) => HashClass.key)).toEqual([...builtinAlgorithms]);
    expect([...builtinAlgorithms].toSorted()).toEqual(files);
  });

  it("names every algorithm the way its info does", () => {
    for (const name of builtinAlgorithms) {
      const algorithm = create(name);
      expect(algorithm.name()).toBe(name);
      expect(algorithm.info().name).toBe(name);
      expect(hashCategories).toContain(algorithm.info().category);
    }
  });

  it("files each algorithm under its lineage, apart from what it is fit for", () => {
    const family = (name: string): string => create(name).info().family;
    const sha = builtinAlgorithms.filter((name) => family(name) === "SHA");

    expect(sha).toEqual([
      "sha256",
      "sha384",
      "sha512",
      "sha512-half",
      "sha3-256",
      "sha3-512",
      "hash256",
      "sha1",
      "sha0",
    ]);
    expect(new Set(sha.map((name) => create(name).info().category))).toEqual(
      new Set(["cryptographic", "legacy"]),
    );
    expect(family("keccak256")).toBe("Keccak");
    expect(family("hash160")).toBe("RIPEMD");
    expect(builtinAlgorithms.filter((name) => family(name) === "BLAKE")).toHaveLength(6);
  });

  it("keeps an algorithm in its family whatever case it spells the family in", () => {
    class LowerSha1 extends Sha1 {
      override info(): AlgorithmInfo {
        return { ...super.info(), family: "sha" };
      }
    }
    register(LowerSha1);
    try {
      expect(algorithmInfos({ family: "SHA" }).map((info) => info.name)).toContain("sha1");
      expect(algorithmInfos({ family: "Sha" }).map((info) => info.name)).toContain("sha256");
    } finally {
      register(Sha1);
    }
  });

  it("answers has() for registered names only", () => {
    expect(has("sha256")).toBe(true);
    expect(has("nonexistent")).toBe(false);
    expect(has("toString")).toBe(false);
  });

  it("credits WireGuard to BLAKE2s, the variant it hashes with", () => {
    const credited = builtinAlgorithms.filter((name) =>
      create(name).info().description.includes("WireGuard"),
    );
    expect(credited).toEqual(["blake2s"]);
  });

  it("registers a class from outside the package", () => {
    class Sha224 extends FixedHash {
      static readonly key = "sha224";
      protected readonly about = {
        label: "SHA-224",
        description: "SHA-2 family 224-bit hash",
        family: "SHA",
        category: "cryptographic",
        digestLength: 28,
      } as const;

      protected digest(bytes: Uint8Array): Uint8Array {
        return createHash("sha224").update(bytes).digest();
      }
    }
    register(Sha224);

    expect(has("sha224")).toBe(true);
    expect(algorithms().at(-1)).toBe("sha224");
    const sha224 = resolveAlgorithm("SHA224");
    expect(sha224).toBeInstanceOf(Sha224);
    expect(sha224.name()).toBe("sha224");
    expect(sha224.info()).toMatchObject({ name: "sha224", hmac: false, digestLength: 28 });
    // FIPS 180-4, the "abc" example.
    expect(sha224.hash("abc").digest).toBe(
      "23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7",
    );
  });

  it("creates one cached instance per key, and a new one after register", () => {
    const first = create("md5");
    expect(create("md5")).toBe(first);
    expect(first).toBeInstanceOf(Hash);

    class Md5Again extends Md5 {}
    register(Md5Again);
    expect(create("md5")).toBeInstanceOf(Md5Again);
    expect(create("md5").hash("hello").digest).toBe("5d41402abc4b2a76b9719d911017c592");
    register(Md5);
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

  it.each(Object.entries(OPENSSL_NAMES))(
    "%s matches OpenSSL on every length through three blocks, whole and as HMAC",
    (name, openssl) => {
      const hash = create(name);
      for (let length = 0; length <= 3 * 136 + 1; length++) {
        const input = new Uint8Array(length).map((_, index) => (index * 7 + length) & 0xff);
        expect(hash.hash(input).digest).toBe(createHash(openssl).update(input).digest("hex"));
      }
      // A view at an odd offset: blocks are read through a DataView, never assumed aligned.
      const shifted = new Uint8Array(301).map((_, index) => index * 3).subarray(1);
      expect(hash.hash(shifted).digest).toBe(createHash(openssl).update(shifted).digest("hex"));
      const message = new Uint8Array(200).map((_, index) => index);
      // Keys around each block size: 64, 72 (sha3-512), 128 and 136 (sha3-256, keccak256).
      for (const length of [0, 1, 63, 64, 65, 71, 72, 73, 127, 128, 129, 135, 136, 137, 300]) {
        const key = new Uint8Array(length).map((_, index) => index * 13);
        expect(hash.hash(message, { key }).digest).toBe(
          createHmac(openssl, key).update(message).digest("hex"),
        );
      }
    },
  );

  it("takes an empty HMAC key as a key, not as no key", () => {
    expect(create("sha256").hash("message", { key: "" }).digest).toBe(
      createHmac("sha256", "").update("message").digest("hex"),
    );
  });

  it("refuses HMAC where the algorithm has none, instead of ignoring the key", () => {
    const without = builtinAlgorithms.filter((name) => !create(name).info().hmac);
    expect(without).toEqual([
      "sha512-half",
      "blake2b-256",
      "blake2b-224",
      "blake3",
      "blake256",
      "hash160",
      "hash256",
      "crc32",
      "crc16-xmodem",
      "xxhash",
      "fnv1a",
      "scrypt",
      "pbkdf2",
      "hkdf",
    ]);
    for (const name of without) {
      expect(() => create(name).hash("message", { key: "secret" })).toThrow(HashError);
    }
  });

  it.each([
    [0, "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262"],
    [1, "2d3adedff11b61f14c886e35afa036736dcd87a74d27b5c1510225d0f592e213"],
    [63, "e9bc37a594daad83be9470df7f7b3798297c3d834ce80ba85d6e207627b7db7b"],
    [64, "4eed7141ea4a5cd4b788606bd23f46e212af9cacebacdc7d1f4c6dc7f2511b98"],
    [65, "de1e5fa0be70df6d2be8fffd0e99ceaa8eb6e8c93a63f2d8d1c30ecb6b263dee"],
    [127, "d81293fda863f008c09e92fc382a81f5a0b4a1251cba1634016a0f86a6bd640d"],
    [128, "f17e570564b26578c33bb7f44643f539624b05df1a76c81f30acd548c44b45ef"],
    [129, "683aaae9f3c5ba37eaaf072aed0f9e30bac0865137bae68b1fde4ca2aebdcb12"],
    [1023, "10108970eeda3eb932baac1428c7a2163b0e924c9a9e25b35bba72b28f70bd11"],
    [1024, "42214739f095a406f3fc83deb889744ac00df831c10daa55189b5d121c855af7"],
    [1025, "d00278ae47eb27b34faecf67b4fe263f82d5412916c1ffd97c8cb7fb814b8444"],
    [2048, "e776b6028c7cd22a4d0ba182a8bf62205d2ef576467e838ed6f2529b85fba24a"],
    [2049, "5f4d72f40d7a5f82b15ca2b2e44b1de3c2ef86c426c95c1af0b6879522563030"],
    [3072, "b98cb0ff3623be03326b373de6b9095218513e64f1ee2edd2525c7ad1e5cffd2"],
    [3073, "7124b49501012f81cc7f11ca069ec9226cecb8a2c850cfe644e327d22d3e1cd3"],
    [4096, "015094013f57a5277b59d8475c0501042c0b642e531b0a1c8f58d2163229e969"],
    [4097, "9b4052b38f1c5fc8b1f9ff7ac7b27cd242487b3d890d15c96a1c25b8aa0fb995"],
    [5121, "628bd2cb2004694adaab7bbd778a25df25c47b9d4155a55f8fbd79f2fe154cff"],
    [6144, "3e2e5b74e048f3add6d21faab3f83aa44d3b2278afb83b80b3c35164ebeca205"],
    [7169, "a003fc7a51754a9b3c7fae0367ab3d782dccf28855a03d435f8cfe74605e7817"],
    [8192, "aae792484c8efe4f19e2ca7d371d8c467ffb10748d8a5a1ae579948f718a2a63"],
    [8193, "bab6c09cb8ce8cf459261398d2e7aef35700bf488116ceb94a36d0f5f1b7bc3b"],
    [16384, "f875d6646de28985646f34ee13be9a576fd515f76b5b0a26bb324735041ddde4"],
    [31744, "62b6960e1a44bcc1eb1a611a8d6235b6b4b78f32e7abc4fb4c6cdcce94895c47"],
    [102400, "bc3e3d41a1146b069abffad3c0d44860cf664390afce4d9661f7902e7943e085"],
  ] as const)(
    "matches the reference BLAKE3 on the official vector lengths (%i bytes of i %% 251)",
    (length, expected) => {
      const input = new Uint8Array(length).map((_, index) => index % 251);
      expect(create("blake3").hash(input).digest).toBe(expected);
    },
  );

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

  it("matches zlib for CRC-32, eight bytes at a time and the tail", () => {
    for (const sample of SAMPLES) {
      expect(create("crc32").hash(sample).digest).toBe(
        zlibCrc32(sample).toString(16).padStart(8, "0"),
      );
    }
    for (let length = 0; length <= 40; length++) {
      const input = new Uint8Array(length).map((_, index) => (index * 37 + length) & 0xff);
      expect(create("crc32").hash(input).digest).toBe(
        zlibCrc32(input).toString(16).padStart(8, "0"),
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

describe("hashes chains use", () => {
  it("hash160 gives the Bitcoin key hash of the generator point", () => {
    // Compressed public key of private key 1; its P2PKH address is 1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH.
    const key = Buffer.from(
      "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
      "hex",
    );
    expect(create("hash160").hash(key).digest).toBe("751e76e8199196d454941c45d1b3a323f1433bd6");
  });

  it("hash256 gives the genesis block hash, byte-reversed as explorers print it", () => {
    const header = Buffer.from(
      "0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a29ab5f49ffff001d1dac2b7c",
      "hex",
    );
    const digest = create("hash256").hash(header, { encoding: "binary" }).digest as Uint8Array;
    expect(Buffer.from(digest).reverse().toString("hex")).toBe(
      "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f",
    );
  });

  it("keccak256 matches the published vectors and differs from sha3-256", () => {
    expect(create("keccak256").hash("").digest).toBe(
      "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470",
    );
    expect(create("keccak256").hash("abc").digest).toBe(
      "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45",
    );
    expect(create("keccak256").hash("abc").digest).not.toBe(create("sha3-256").hash("abc").digest);
  });

  it("sha0 matches the FIPS 180 vectors and differs from sha1", () => {
    // FIPS 180 (1993), appendices A, B and C; OpenSSL and hashlib no longer ship SHA-0.
    expect(create("sha0").hash("abc").digest).toBe("0164b8a914cd2a5e74c4f7ff082c4d97f1edf880");
    expect(
      create("sha0").hash("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq").digest,
    ).toBe("d2516ee1acfa5baf33dfc1c471e438449ef134c8");
    expect(create("sha0").hash("a".repeat(1_000_000)).digest).toBe(
      "3232affa48628a26653b5aaa44541fd90d690603",
    );
    expect(create("sha0").hash("").digest).toBe("f96cea198ad1dd5617ac084a3d92c6107708c0ef");
    expect(create("sha0").hash("abc").digest).not.toBe(create("sha1").hash("abc").digest);
  });

  it("blake2b-256 and blake2b-224 match the reference BLAKE2b", () => {
    // Python hashlib.blake2b(data, digest_size=32 or 28).
    expect(create("blake2b-256").hash("").digest).toBe(
      "0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8",
    );
    expect(create("blake2b-256").hash("abc").digest).toBe(
      "bddd813c634239723171ef3fee98579b94964e3bb1cb3e427262c8c068d52319",
    );
    expect(create("blake2b-224").hash("abc").digest).toBe(
      "9bd237b02a29e43bdd6738afa5b53ff0eee178d6210b618e4511aec8",
    );
  });

  it("blake256 matches the BLAKE submission's test vectors", () => {
    expect(create("blake256").hash("").digest).toBe(
      "716f6e863f744b9ac22c97ec7b76ea5f5908bc5b2f67c61510bfc4751384ea7a",
    );
    expect(create("blake256").hash(new Uint8Array(1)).digest).toBe(
      "0ce8d4ef4dd7cd8d62dfded9d4edb0a774ae6a41929a74da23109e8f11139c87",
    );
    expect(create("blake256").hash(new Uint8Array(72)).digest).toBe(
      "d419bad32d504fb7d44d460c42c5593fe544fa4c135dec31e21bd9abdcc22d41",
    );
  });

  it("sha512-half is the first half of SHA-512", () => {
    expect(create("sha512-half").hash("abc").digest).toBe(
      "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a",
    );
  });

  it("crc16-xmodem matches the catalogue check value", () => {
    expect(create("crc16-xmodem").hash("123456789").digest).toBe("31c3");
    expect(create("crc16-xmodem").hash("").digest).toBe("0000");
  });
});

describe("byte functions", () => {
  /** Lengths around every block size and the padding edge of each hash. */
  const LENGTHS = [
    0, 1, 20, 27, 28, 32, 33, 55, 56, 63, 64, 65, 111, 112, 127, 128, 129, 135, 136, 137, 1000,
  ];
  const inputs = LENGTHS.map((length) =>
    Uint8Array.from({ length }, (_, i) => (i * 131 + length) & 0xff),
  );
  const binary = (name: string, bytes: Uint8Array): Uint8Array =>
    create(name).hash(bytes, { encoding: "binary" }).digest as Uint8Array;

  it("give the registry's digest for every length", () => {
    const functions = {
      md5,
      sha1,
      sha256,
      sha512,
      ripemd160,
      hash160,
      hash256,
      keccak256,
      "sha3-256": sha3_256,
      blake256,
      "blake2b-256": (bytes: Uint8Array) => blake2b(bytes, 32),
      "blake2b-224": (bytes: Uint8Array) => blake2b(bytes, 28),
      blake2b: (bytes: Uint8Array) => blake2b(bytes, 64),
      crc32,
      "crc16-xmodem": crc16Xmodem,
    };
    for (const [name, digest] of Object.entries(functions)) {
      for (const bytes of inputs)
        expect(digest(bytes), `${name} of ${bytes.length}`).toEqual(binary(name, bytes));
    }
  });

  it("match Node for the digests OpenSSL and zlib compute", () => {
    for (const bytes of inputs) {
      expect(md5(bytes).toHex()).toBe(createHash("md5").update(bytes).digest("hex"));
      expect(sha1(bytes).toHex()).toBe(createHash("sha1").update(bytes).digest("hex"));
      expect(sha256(bytes).toHex()).toBe(createHash("sha256").update(bytes).digest("hex"));
      expect(sha512(bytes).toHex()).toBe(createHash("sha512").update(bytes).digest("hex"));
      expect(ripemd160(bytes).toHex()).toBe(createHash("ripemd160").update(bytes).digest("hex"));
      expect(sha3_256(bytes).toHex()).toBe(createHash("sha3-256").update(bytes).digest("hex"));
      expect(new DataView(crc32(bytes).buffer).getUint32(0)).toBe(zlibCrc32(bytes));
    }
  });

  it("return a Uint8Array of the digest's length", () => {
    for (const [digest, length] of [
      [sha256(new Uint8Array(1)), 32],
      [hash160(new Uint8Array(1)), 20],
      [blake2b(new Uint8Array(1), 1), 1],
      [crc16Xmodem(new Uint8Array(1)), 2],
    ] as const) {
      expect(digest).toBeInstanceOf(Uint8Array);
      expect(digest).toHaveLength(length);
    }
  });

  it("take a Buffer and a subarray as the bytes they show", () => {
    const bytes = Buffer.from("zażółć gęślą jaźń");
    const framed = new Uint8Array(bytes.length + 8);
    framed.set(bytes, 4);
    expect(sha256(bytes)).toEqual(sha256(new Uint8Array(bytes)));
    expect(sha256(framed.subarray(4, 4 + bytes.length))).toEqual(sha256(new Uint8Array(bytes)));
  });

  it("run HMAC and PBKDF2 over an exported hasher as Node does", () => {
    const hashers = {
      sha256: () => new Sha256Hasher(),
      sha512: () => new Sha512Hasher(),
      ripemd160: () => new Ripemd160Hasher(),
    };
    const password = new TextEncoder().encode("abandon ability able about above absent");
    const salt = new TextEncoder().encode("mnemonic");
    for (const [name, create] of Object.entries(hashers)) {
      for (const key of [
        new Uint8Array(0),
        new Uint8Array(20).fill(0x0b),
        new Uint8Array(200).fill(0xaa),
      ]) {
        for (const bytes of inputs) {
          expect(hmac(create, key, bytes).toHex()).toBe(
            createHmac(name, key).update(bytes).digest("hex"),
          );
        }
      }
      expect(pbkdf2(create, password, salt, 2048, 64).toHex()).toBe(
        pbkdf2Sync(password, salt, 2048, 64, name).toString("hex"),
      );
    }
    expect(hmac(() => new Blake2bHasher(64), new Uint8Array(3), new Uint8Array(3))).toEqual(
      create("blake2b").hash(new Uint8Array(3), { key: new Uint8Array(3), encoding: "binary" })
        .digest,
    );
  });

  it("derive the RFC 5869 SHA-256 test cases 1 and 3 with HKDF", () => {
    const sha256Hasher = () => new Sha256Hasher();
    const ikm = new Uint8Array(22).fill(0x0b);
    const salt = Uint8Array.fromHex("000102030405060708090a0b0c");
    const info = Uint8Array.fromHex("f0f1f2f3f4f5f6f7f8f9");
    const prk = hkdfExtract(sha256Hasher, salt, ikm);
    expect(prk.toHex()).toBe("077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5");
    expect(hkdfExpand(sha256Hasher, prk, info, 42).toHex()).toBe(
      "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865",
    );
    const empty = new Uint8Array(0);
    expect(hkdfExtract(sha256Hasher, empty, ikm).toHex()).toBe(
      "19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04",
    );
    expect(hkdf(sha256Hasher, ikm, empty, empty, 42).toHex()).toBe(
      "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8",
    );
  });

  it("run HKDF over an exported hasher as Node does, up to 255 blocks", () => {
    const hashers = {
      sha256: () => new Sha256Hasher(),
      sha512: () => new Sha512Hasher(),
      ripemd160: () => new Ripemd160Hasher(),
    };
    const ikm = new TextEncoder().encode("shared secret");
    const info = new Uint8Array(80).map((_, i) => 0xb0 + i);
    for (const [name, create] of Object.entries(hashers)) {
      const hashLength = create().outputLength;
      for (const salt of [new Uint8Array(0), new Uint8Array(13), new Uint8Array(200).fill(0xaa)]) {
        for (const length of [1, hashLength - 1, hashLength, hashLength + 1, 255 * hashLength]) {
          expect(hkdf(create, ikm, salt, info, length).toHex(), `${name} ${length}`).toBe(
            Buffer.from(hkdfSync(name, ikm, salt, info, length)).toString("hex"),
          );
        }
      }
      for (const length of [0, 255 * hashLength + 1, 1.5, Number.NaN]) {
        expect(() => hkdf(create, ikm, new Uint8Array(0), info, length)).toThrow(
          InvalidOptionError,
        );
      }
    }
  });

  it("refuse anything but bytes instead of hashing it as something else", () => {
    const loose = (value: unknown) => value as Uint8Array;
    expect(() => sha256(loose("abc"))).toThrow(
      new HashError("data must be a Uint8Array, not string"),
    );
    expect(() => keccak256(loose([1, 2, 3]))).toThrow(
      new HashError("data must be a Uint8Array, not object"),
    );
    expect(() => blake256(loose(null))).toThrow(
      new HashError("message must be a Uint8Array, not null"),
    );
    expect(() => crc32(loose(new ArrayBuffer(4)))).toThrow(HashError);
    expect(() => blake2b(new Uint8Array(1), 64, loose("UA_F4Jumble_H"))).toThrow(
      new HashError("personalization must be a Uint8Array, not string"),
    );
    for (const hasher of [
      new Sha256Hasher(),
      new Sha512Hasher(),
      new Ripemd160Hasher(),
      new Blake2bHasher(32),
    ]) {
      expect(() => hasher.update(loose("abc"))).toThrow(
        new HashError("data must be a Uint8Array, not string"),
      );
    }
    expect(() => hmac(() => new Sha256Hasher(), loose("key"), new Uint8Array(0))).toThrow(
      new HashError("key must be a Uint8Array, not string"),
    );
    expect(() => pbkdf2(() => new Sha256Hasher(), new Uint8Array(1), loose("salt"), 1, 32)).toThrow(
      new HashError("salt must be a Uint8Array, not string"),
    );
    expect(() =>
      hkdf(() => new Sha256Hasher(), new Uint8Array(1), new Uint8Array(0), loose("info"), 32),
    ).toThrow(new HashError("info must be a Uint8Array, not string"));
  });

  it("build SHA-512 at 64 bytes and SHA-384 at 48, nothing in between", () => {
    const bytes = new Uint8Array([1, 2, 3]);
    expect(new Sha512Hasher(48).update(bytes).digest().toHex()).toBe(
      createHash("sha384").update(bytes).digest("hex"),
    );
    for (const length of [32, 0, Number.NaN]) {
      expect(() => new Sha512Hasher(length as 64)).toThrow(InvalidOptionError);
    }
  });

  it("refuse a BLAKE2b length outside 1 to 64 bytes", () => {
    for (const length of [0, 65, 1.5, Number.NaN]) {
      expect(() => blake2b(new Uint8Array(1), length)).toThrow(InvalidOptionError);
      expect(() => new Blake2bHasher(length)).toThrow(InvalidOptionError);
    }
  });

  it("personalize BLAKE2b as Python's hashlib does", () => {
    const ascii = (text: string) => new TextEncoder().encode(text);
    // Python hashlib.blake2b(data, digest_size=length, person=personalization).
    for (const [data, length, personalization, digest] of [
      [
        new Uint8Array(0),
        64,
        Uint8Array.from([...ascii("UA_F4Jumble_H"), 0, 0, 0]),
        "c74ca4ba9f11b8300b364aadef413c9b7379d5e2f4110c109ff943d1bf446957087720638d6d3c91f7a9067d51ddf3c52ac959ceaaee3cbd5071cef72fcfc21d",
      ],
      [
        ascii("abc"),
        64,
        Uint8Array.from([...ascii("UA_F4Jumble_G"), 1, 2, 1]),
        "3ca7f474c174bd0115190e1e09451055928a8a4da3718edd2ea6ecf507299372fe5b8c47024be81342ac9af3b5bc47151a98c9236af15afc86680a5624467032",
      ],
      [
        Uint8Array.from({ length: 200 }, (_, i) => i),
        38,
        ascii("ZcashPoW"),
        "de9a31a73652820f2eae61766383ecef002e53307324026506e915b4e04e126eb37644232e53",
      ],
      [
        Uint8Array.from({ length: 128 }, (_, i) => i),
        32,
        ascii("0123456789abcdef"),
        "68f5bac43bc706250ecbf60870c6e7c556f62ab2e572d17d6da79e07667a91fa",
      ],
    ] as const) {
      expect(blake2b(data, length, personalization).toHex()).toBe(digest);
    }
    const bytes = new Uint8Array([1, 2, 3]);
    expect(blake2b(bytes, 64, new Uint8Array(0))).toEqual(blake2b(bytes, 64));
    expect(blake2b(bytes, 64, new Uint8Array(16))).toEqual(blake2b(bytes, 64));
  });

  it("jumble a Zcash Unified Address with personalized BLAKE2b", () => {
    const personal = (tag: string, round: number, block = 0) =>
      Uint8Array.from([...new TextEncoder().encode(tag), round, block & 0xff, block >>> 8]);
    const xor = (bytes: Uint8Array, mask: Uint8Array) =>
      bytes.map((byte, index) => byte ^ mask[index]!);
    const expand = (round: number, input: Uint8Array, length: number) => {
      const out = new Uint8Array(Math.ceil(length / 64) * 64);
      for (let block = 0; block * 64 < length; block++)
        out.set(blake2b(input, 64, personal("UA_F4Jumble_G", round, block)), block * 64);
      return out.subarray(0, length);
    };
    // ZIP 316 F4Jumble forwards, against zcash-test-vectors `f4jumble.json`, normal then jumbled.
    for (const [normal, jumbled] of [
      [
        "5d7a8f739a2d9e945b0ce152a8049e294c4d6e66b164939daffa2ef6ee6921481cdd86b3cc4318d9614fc820905d042b",
        "0304d029141b995da5387c125970673504d6c764d91ea6c082123770c7139ccd88ee27368cd0c0921a0444c8e5858d22",
      ],
      [
        "b1ef9ca3f24988c7b3534201cfb1cd8dbf69b8250c18ef41294ca97993db546c1fe01f7e9c8e36d6a5e29d4e30a73594bf5098421c69378af1e40f64e125946f",
        "5271fa3321f3adbcfb075196883d542b438ec6339176537daf859841fe6a56222bff76d1662b5509a9e1079e446eeedd2e683c31aae3ee1851d7954328526be1",
      ],
      [
        "62c2fa7b2fecbcb64b6968912a6381ce3dc166d56a1d62f5a8d7551db5fd9313e8c7203d996af7d477083756d59af80d06a745f44ab023752cb5b406ed8985e18130ab33362697b0e4e4c763ccb8f676495c222f7fba1e31defa3d5a57efc2e1e9b01a035587d5fb1a38e01d94903d3c3e0ad3360c1d3710acd20b183e31d49f",
        "498cf1b1ba6f4577effe64151d67469adc30acc325e326207e7d78487085b4162669f82f02f9774c0cc26ae6e1a76f1e266c6a9a8a2f4ffe8d2d676b1ed71cc47195a3f19208998f7d8cdfc0b74d2a96364d733a62b4273c77d9828aa1fa061588a7c4c88dd3d3dde02239557acfaad35c55854f4541e1a1b3bc8c17076e7316",
      ],
      [
        "25c9a138f49b1a537edcf04be34a9851a7af9db6990ed83dd64af3597c04323ea51b0052ad8084a8b9da948d320dadd64f5431e61ddf658d24ae67c22c8d1309131fc00fe7f235734276d38d47f1e191e00c7a1d48af046827591e9733a97fa6b679f3dc601d008285edcbdae69ce8fc1be4aac00ff2711ebd931de518856878f7",
        "7508a3a146714f229db91b543e240633ed57853f6451c9db6d64c6e86af1b88b28704f608582c53c51ce7d5b8548827a971d2b98d41b7f6258655902440cd66ee11e84dbfac7d2a43696fd0468810a3d9637c3fa58e7d2d341ef250fa09b9fb71a78a41d389370138a55ea58fcde779d714a04e0d30e61dc2d8be0da61cd684509",
      ],
    ]) {
      const message = Uint8Array.fromHex(normal!);
      const leftLength = Math.min(64, Math.floor(message.length / 2));
      const a = message.subarray(0, leftLength);
      const b = message.subarray(leftLength);
      const x = xor(b, expand(0, a, b.length));
      const y = xor(a, blake2b(x, leftLength, personal("UA_F4Jumble_H", 0)));
      const d = xor(x, expand(1, y, x.length));
      const c = xor(y, blake2b(d, leftLength, personal("UA_F4Jumble_H", 1)));
      expect(c.toHex() + d.toHex()).toBe(jumbled);
    }
  });

  it("refuse a BLAKE2b personalization longer than 16 bytes", () => {
    expect(() => blake2b(new Uint8Array(1), 64, new Uint8Array(17))).toThrow(InvalidOptionError);
    expect(() => new Blake2bHasher(64, new Uint8Array(17))).toThrow(InvalidOptionError);
  });

  it("refuse PBKDF2 costs and lengths that are not positive integers", () => {
    const derive = (iterations: number, keyLength: number) =>
      pbkdf2(() => new Sha256Hasher(), new Uint8Array(1), new Uint8Array(1), iterations, keyLength);
    for (const bad of [0, -1, 1.5, Number.NaN, Number.POSITIVE_INFINITY]) {
      expect(() => derive(bad, 32)).toThrow(InvalidOptionError);
      expect(() => derive(1, bad)).toThrow(InvalidOptionError);
    }
  });
});

describe("byte function subpaths", () => {
  const SUBPATHS = {
    sha1: ["sha1"],
    md5: ["md5"],
    sha2: ["Sha256Hasher", "Sha512Hasher", "hash256", "sha256", "sha512"],
    ripemd160: ["Ripemd160Hasher", "hash160", "ripemd160"],
    keccak: ["keccak256", "sha3_256"],
    blake2b: ["Blake2bHasher", "blake2b"],
    blake256: ["blake256"],
    crc: ["crc16Xmodem", "crc32"],
    hmac: ["hkdf", "hkdfExpand", "hkdfExtract", "hmac", "pbkdf2"],
  } as const;
  const names = Object.keys(SUBPATHS);

  it("match the exports map and the build entries", () => {
    const exported = Object.keys(pkg.exports).filter((path) => !/^\.(?:\/ai|\/mcp)?$/u.test(path));
    const inputs = buildConfig.entries?.flatMap((entry) =>
      typeof entry === "object" && entry.type === "bundle" ? [entry.input].flat() : [],
    );

    expect(exported).toEqual(names.map((name) => `./${name}`));
    expect(inputs).toEqual(expect.arrayContaining(names.map((name) => `./src/${name}.ts`)));
  });

  it.each(Object.entries(SUBPATHS))(
    "%s exports the root's functions and nothing else",
    async (name, expected) => {
      const module = (await import(`../src/${name}.ts`)) as Record<string, unknown>;

      expect(Object.keys(module).toSorted()).toEqual([...expected].toSorted());
      for (const key of expected) expect(module[key]).toBe(root[key]);
    },
  );
});

describe("rounds", () => {
  /* Node's digest looped as many rounds, each over the last digest's bytes or its hex. */
  function nodeRounds(name: string, input: string, rounds: number, chain: "bytes" | "hex") {
    let digest = createHash(name).update(input).digest();
    for (let round = 1; round < rounds; round++) {
      digest = createHash(name)
        .update(chain === "hex" ? digest.toString("hex") : digest)
        .digest();
    }
    return digest.toString("hex");
  }

  it("matches Node looping over the bytes or the hex of each digest", () => {
    for (const [name, node] of [
      ["sha256", "sha256"],
      ["sha512", "sha512"],
      ["sha3-256", "sha3-256"],
      ["md5", "md5"],
      ["ripemd160", "ripemd160"],
    ] as const) {
      for (const chain of ["bytes", "hex"] as const) {
        expect(create(name).hash("abc", { rounds: 1000, chain }).digest).toBe(
          nodeRounds(node, "abc", 1000, chain),
        );
      }
    }
  });

  it("chains bytes by default and reports rounds and chain only past one round", () => {
    const sha256 = create("sha256");
    expect(sha256.hash("abc", { rounds: 2 }).digest).toBe(nodeRounds("sha256", "abc", 2, "bytes"));
    expect(sha256.hash("abc", { rounds: 2 }).options).toEqual({
      encoding: "hex",
      rounds: 2,
      chain: "bytes",
    });
    expect(sha256.hash("abc", { rounds: 1, chain: "hex" })).toEqual(sha256.hash("abc"));
    expect(create("xxhash").hash("abc", { rounds: 2, seed: 1 } as XxhashOptions).options).toEqual({
      encoding: "hex",
      seed: 1,
      rounds: 2,
      chain: "bytes",
    });
  });

  it("is an option of every fixed-length digest and of no KDF", () => {
    for (const name of builtinAlgorithms) {
      const names = create(name)
        .info()
        .options.map((option) => option.name);
      const kdf = name === "scrypt" || name === "pbkdf2" || name === "hkdf";
      expect(names.includes("rounds") && names.includes("chain"), name).toBe(!kdf);
    }
  });

  it("refuses rounds that are not a positive integer and an unknown chain", () => {
    const sha256 = create("sha256");
    const loose = (value: object) => value as HashOptions;
    for (const rounds of [0, -1, 1.5, Number.NaN, 2 ** 31, "3"]) {
      expect(() => sha256.hash("abc", loose({ rounds }))).toThrow(InvalidOptionError);
    }
    expect(() => sha256.hash("abc", loose({ chain: "base64" }))).toThrow(
      "Invalid option chain=base64: use bytes or hex",
    );
  });

  it("refuses rounds for HMAC and the KDFs instead of running one", () => {
    expect(() => create("sha256").hash("abc", { key: "k", rounds: 2 })).toThrow(
      "Invalid option rounds=2: HMAC runs one round",
    );
    expect(() => create("pbkdf2").hash("abc", { salt: "00", rounds: 2 } as Pbkdf2Options)).toThrow(
      "pbkdf2 sets its cost with its own parameters",
    );
    expect(() => create("scrypt").hash("abc", { salt: "00", rounds: 2 } as ScryptOptions)).toThrow(
      "scrypt sets its cost with its own parameters",
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
    for (const digest of ["sha256", "sha384", "sha512", "sha3-256", "sha3-512"]) {
      const result = create("pbkdf2").hash("password", {
        salt,
        iterations: 1000,
        digest,
      } as Pbkdf2Options);
      expect(result.digest).toBe(
        pbkdf2Sync("password", Buffer.from(salt, "hex"), 1000, 64, digest).toString("hex"),
      );
    }
    // A key longer than one digest takes more than one block, and the last one is cut.
    const long = create("pbkdf2").hash("password", {
      salt,
      iterations: 3,
      digest: "sha256",
      keyLength: 100,
    } as Pbkdf2Options);
    expect(long.digest).toBe(
      pbkdf2Sync("password", Buffer.from(salt, "hex"), 3, 100, "sha256").toString("hex"),
    );
  });

  it("matches Node's HKDF for every digest it offers and reports salt and info", () => {
    const ikm = Uint8Array.fromHex("0b".repeat(22));
    const info = "f0f1f2f3f4f5f6f7f8f9";
    for (const digest of ["sha256", "sha384", "sha512", "sha3-256", "sha3-512"]) {
      const result = create("hkdf").hash(ikm, { salt, info, digest, keyLength: 42 } as HkdfOptions);
      expect(result.digest).toBe(
        Buffer.from(
          hkdfSync(digest, ikm, Buffer.from(salt, "hex"), Buffer.from(info, "hex"), 42),
        ).toString("hex"),
      );
      expect(result.options).toEqual({ encoding: "hex", digest, keyLength: 42, salt, info });
    }
  });

  it("reads a missing HKDF salt as zeros instead of drawing one", () => {
    const result = create("hkdf").hash("secret");
    expect(result.digest).toBe(
      Buffer.from(hkdfSync("sha256", "secret", new Uint8Array(32), "", 32)).toString("hex"),
    );
    expect(result.options).toEqual({ encoding: "hex", digest: "sha256", keyLength: 32 });
    expect(create("hkdf").hash("secret").digest).toBe(result.digest);
  });

  it("refuses an HKDF info that is not hex and a key past 255 digests", () => {
    const hkdf = create("hkdf");
    expect(() => hkdf.hash("x", { info: "0x01" } as HkdfOptions)).toThrow(
      "Invalid option info=4 characters: must be hex digit pairs, without a 0x prefix",
    );
    expect(() => hkdf.hash("x", { keyLength: 255 * 32 + 1 } as HkdfOptions)).toThrow(
      "Invalid option keyLength=8161: must be 1 to 8160 bytes",
    );
    expect(
      hkdf.hash("x", { digest: "sha512", keyLength: 255 * 64 } as HkdfOptions).digestLength,
    ).toBe(255 * 64);
    expect(() => hkdf.hash("x", { digest: "md5" } as HkdfOptions)).toThrow(
      "Invalid option digest=md5",
    );
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

  it("derives with a tiny N", () => {
    const result = create("scrypt").hash("pw", {
      salt,
      N: 2,
      r: 1,
      p: 1,
      keyLength: 16,
    } as ScryptOptions);
    expect(result.digest).toBe(
      scryptSync("pw", Buffer.from(salt, "hex"), 16, { N: 2, r: 1, p: 1 }).toString("hex"),
    );
  });

  it("refuses an empty salt as bytes, as it does as text", () => {
    for (const empty of [new Uint8Array(0), ""]) {
      expect(() =>
        create("pbkdf2").hash("pw", { salt: empty, iterations: 1 } as Pbkdf2Options),
      ).toThrow(/Invalid option salt=/);
    }
  });

  it("matches the RFC 7914 vector with p above 1", () => {
    const result = create("scrypt").hash("password", {
      salt: "NaCl",
      saltEncoding: "utf8",
      N: 1024,
      r: 8,
      p: 16,
    } as ScryptOptions);
    expect(result.digest).toBe(
      "fdbabe1c9d3472007856e7190d01e9fe7c6ad7cbc8237830e77376634b3731622eaf30d92e22a3886ff109279d9830dac727afb94a83ee6d8360cbdfa2cc0640",
    );
  });

  it("refuses the costs RFC 7914 rules out, as OpenSSL did", () => {
    expect(() => create("scrypt").hash("pw", { salt, N: 65536, r: 1 } as ScryptOptions)).toThrow(
      /Invalid option N=65536/,
    );
    expect(
      create("scrypt").hash("pw", { salt, N: 32768, r: 1, keyLength: 16 } as ScryptOptions).digest,
    ).toBe(
      scryptSync("pw", Buffer.from(salt, "hex"), 16, { N: 32768, r: 1, p: 1 }).toString("hex"),
    );
    expect(() =>
      create("scrypt").hash("pw", { salt, N: 2, r: 1, p: 2 ** 24 } as ScryptOptions),
    ).toThrow(/Invalid option p=16777216/);
  });

  it("refuses costs and key lengths above a C int before any work, as OpenSSL did", () => {
    const tooLarge = 2 ** 31;
    expect(() =>
      create("pbkdf2").hash("pw", { salt, iterations: tooLarge } as Pbkdf2Options),
    ).toThrow(/Invalid option iterations=2147483648/);
    expect(() =>
      create("pbkdf2").hash("pw", { salt, iterations: 1, keyLength: tooLarge } as Pbkdf2Options),
    ).toThrow(/Invalid option keyLength=2147483648/);
    expect(() =>
      create("scrypt").hash("pw", { salt, N: 2, r: 1, keyLength: tooLarge } as ScryptOptions),
    ).toThrow(/Invalid option keyLength=2147483648/);
  });

  it("refuses zero r, p and keyLength", () => {
    for (const cost of [{ r: 0 }, { p: 0 }, { keyLength: 0 }]) {
      expect(() =>
        create("scrypt").hash("pw", { salt, N: 1024, ...cost } as ScryptOptions),
      ).toThrow(/must be a positive integer/);
    }
    expect(() => create("pbkdf2").hash("pw", { salt, keyLength: 0 } as Pbkdf2Options)).toThrow(
      /must be a positive integer/,
    );
  });

  it("states collision and preimage strength apart", () => {
    expect(create("sha256").info().securityNote).toMatch(
      /^128-bit collision resistance, 256-bit preimage/,
    );
    expect(create("hash160").info().securityNote).toMatch(/^80-bit collision resistance/);
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
      new DependencyError("argon2id", "argon2"),
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
    expect(new DependencyError("argon2id", "argon2").message).toContain("argon2");
  });

  it("normalizes foreign errors", () => {
    const own = new UnknownAlgorithmError("foo");
    expect(normalizeError(own)).toBe(own);
    expect(normalizeError(new Error("disk full")).message).toBe("disk full");
    expect(normalizeError("oops")).toBeInstanceOf(HashError);
    expect(normalizeError(new Error("bad input"), "fnv1a").message).toBe("[fnv1a] bad input");
  });
});

describe("runtime", () => {
  it("imports the library and runs every algorithm with node:* blocked", () => {
    const entry = new URL("../src/index.ts", import.meta.url).href;
    const script = `
      import { builtinModules, registerHooks } from "node:module";
      const builtin = new Set(builtinModules);
      registerHooks({
        resolve(specifier, context, next) {
          if (specifier.startsWith("node:") || builtin.has(specifier)) {
            throw new Error("blocked " + specifier + " from " + context.parentURL);
          }
          return next(specifier, context);
        },
      });
      await import("node:fs").then(
        () => { throw new Error("the hook let node:fs through"); },
        () => {},
      );
      const { algorithms, create, digestMatches } = await import(${JSON.stringify(entry)});
      const costs = { scrypt: { N: 16 }, pbkdf2: { iterations: 1 } };
      for (const name of algorithms()) {
        const hash = create(name);
        const result = hash.hash("abc", costs[name]);
        if (!digestMatches(result, result.digest)) throw new Error(name + " does not match itself");
        if (hash.info().hmac) hash.hash("abc", { key: "key" });
      }
      console.log(algorithms().join(","));
    `;
    const output = execFileSync(process.execPath, ["--input-type=module", "-e", script], {
      encoding: "utf8",
    });
    expect(output.trim()).toBe(builtinAlgorithms.join(","));
  });
});
