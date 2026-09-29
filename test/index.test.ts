import { execFileSync } from "node:child_process";
import { createHash, createHmac, pbkdf2Sync, scryptSync } from "node:crypto";
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
  hmac,
  keccak256,
  normalizeError,
  pbkdf2,
  register,
  resolveAlgorithm,
  ripemd160,
  sha256,
  sha3_256,
  sha512,
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

  it("refuse PBKDF2 costs and lengths that are not positive integers", () => {
    const derive = (iterations: number, keyLength: number) =>
      pbkdf2(() => new Sha256Hasher(), new Uint8Array(1), new Uint8Array(1), iterations, keyLength);
    for (const bad of [0, -1, 1.5, Number.NaN, Number.POSITIVE_INFINITY]) {
      expect(() => derive(bad, 32)).toThrow(InvalidOptionError);
      expect(() => derive(1, bad)).toThrow(InvalidOptionError);
    }
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
