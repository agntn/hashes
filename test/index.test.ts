import { execFileSync } from "node:child_process";
import { argon2Sync, createHash, createHmac, hkdfSync, pbkdf2Sync, scryptSync } from "node:crypto";
import { readdirSync } from "node:fs";
import { crc32 as zlibCrc32 } from "node:zlib";
import { describe, expect, it } from "vite-plus/test";
import { Md5, Sha1, builtins } from "../src/algorithms/index.ts";
import { algorithmInfos } from "../src/core/resolve.ts";
import { Sha224Hasher, Sha512tHasher } from "../src/core/sha2.ts";
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
  Md5Hasher,
  Ripemd160Hasher,
  Sha1Hasher,
  Sha256Hasher,
  Sha512Hasher,
  algorithms,
  argon2d,
  argon2i,
  argon2id,
  blake256,
  extendDigest,
  extendableAlgorithms,
  identifyDigest,
  blake2b,
  builtinAlgorithms,
  crc16Xmodem,
  crc32,
  create,
  digestMatches,
  evpBytesToKey,
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
  scrypt,
  sha1,
  sha256,
  sha3_256,
  sha512,
  version,
  type HashOptions,
  type Argon2Options,
  type EvpBytesToKeyOptions,
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
  sha224: "sha224",
  "sha512-224": "sha512-224",
  "sha512-256": "sha512-256",
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
      "sha224",
      "sha512-224",
      "sha512-256",
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
    class Sha3_384 extends FixedHash {
      static readonly key = "sha3-384";
      protected readonly about = {
        label: "SHA3-384",
        description: "SHA-3 family 384-bit hash",
        family: "SHA",
        category: "cryptographic",
        digestLength: 48,
      } as const;

      protected digest(bytes: Uint8Array): Uint8Array {
        return createHash("sha3-384").update(bytes).digest();
      }
    }
    register(Sha3_384);

    expect(has("sha3-384")).toBe(true);
    expect(algorithms().at(-1)).toBe("sha3-384");
    const sha3_384 = resolveAlgorithm("SHA3_384");
    expect(sha3_384).toBeInstanceOf(Sha3_384);
    expect(sha3_384.name()).toBe("sha3-384");
    expect(sha3_384.info()).toMatchObject({ name: "sha3-384", hmac: false, digestLength: 48 });
    /** FIPS 202, the "abc" example. */
    expect(sha3_384.hash("abc").digest).toBe(
      "ec01498288516fc926459f58e2c6ad8df9b473cb0fc08c2596da7cf0e49be4b298d88cea927ac7f539f1edf228376d25",
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
      "ntlm",
      "crc32",
      "crc16-xmodem",
      "xxhash",
      "fnv1a",
      "scrypt",
      "pbkdf2",
      "hkdf",
      "evp-bytestokey",
      "argon2id",
      "argon2i",
      "argon2d",
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

  it("matches the reference XXH64 on every tail and stripe up to 100 bytes", () => {
    /** SHA-256 of the 303 digests the reference xxhash-wasm 1.1.0 gives for these inputs. */
    const reference = "a6f10f37e9ac5e3ec29e2987daddb3feb430b9afec342fa1dda286a4f94fd17d";
    const digests = createHash("sha256");
    for (const seed of [0, 4294967297, "18446744073709551615"]) {
      for (let length = 0; length <= 100; length++) {
        const input = new Uint8Array(length).map((_, index) => (index * 37 + length) & 0xff);
        digests.update(create("xxhash").hash(input, { seed } as XxhashOptions).digest);
      }
    }
    expect(digests.digest("hex")).toBe(reference);
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

  it("md4 matches the RFC 1320 vectors", () => {
    for (const [input, digest] of [
      ["", "31d6cfe0d16ae931b73c59d7e0c089c0"],
      ["a", "bde52cb31de33e46245e05fbdbd6fb24"],
      ["abc", "a448017aaf21d8525fc10ae87aa6729d"],
      ["message digest", "d9130a8164549fe818874806e1c7014b"],
      ["abcdefghijklmnopqrstuvwxyz", "d79e1c308aa5bbcdeea8ed63df412da9"],
      [
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
        "043f8582f241db351ce627e153e7f0e4",
      ],
      ["1234567890".repeat(8), "e33b4ddc9c38f2199c3e7b164fcc0536"],
    ]) {
      expect(create("md4").hash(input!).digest).toBe(digest);
    }
  });

  it("ntlm hashes the password as UTF-16LE, a BOM included", () => {
    /** `printf %s <password> | iconv -t utf-16le | rhash --md4 -`. */
    expect(create("ntlm").hash("password").digest).toBe("8846f7eaee8fb117ad06bdd830b7586c");
    expect(create("ntlm").hash("").digest).toBe("31d6cfe0d16ae931b73c59d7e0c089c0");
    expect(create("ntlm").hash("Zażółć").digest).toBe("77ea2deb8eb6fb24fce4bf693f010787");
    expect(create("ntlm").hash("fox 🦊").digest).toBe("201f5a9dce227da42aa1fd00d10d3339");
    expect(create("ntlm").hash("\uFEFFabc").digest).toBe("e7e52b5469f2a7d9a9231dac50e030ae");
    expect(create("ntlm").hash(new TextEncoder().encode("password")).digest).toBe(
      "8846f7eaee8fb117ad06bdd830b7586c",
    );
  });

  it("ntlm refuses bytes that are not UTF-8 text", () => {
    expect(() => create("ntlm").hash(new Uint8Array([0xff]))).toThrow(
      new HashError("ntlm hashes text, and the input is not valid UTF-8"),
    );
  });

  it("ripemd128, ripemd256 and ripemd320 match the RIPEMD authors' vectors", () => {
    /** The RIPEMD page's vectors, which RustCrypto's ripemd 0.1.3 computes too. */
    const vectors = [
      [
        "",
        "cdf26213a150dc3ecb610f18f6b38b46",
        "02ba4c4e5f8ecd1877fc52d64d30e37a2d9774fb1e5d026380ae0168e3c5522d",
        "22d65d5661536cdc75c1fdf5c6de7b41b9f27325ebc61e8557177d705a0ec880151c3a32a00899b8",
      ],
      [
        "abc",
        "c14a12199c66e4ba84636b0f69144c77",
        "afbd6e228b9d8cbbcef5ca2d03e6dba10ac0bc7dcbe4680e1e42d2e975459b65",
        "de4c01b3054f8930a79d09ae738e92301e5a17085beffdc1b8d116713e74f82fa942d64cdbc4682d",
      ],
      [
        "message digest",
        "9e327b3d6e523062afc1132d7df9d1b8",
        "87e971759a1ce47a514d5c914c392c9018c7c46bc14465554afcdf54a5070c0e",
        "3a8e28502ed45d422f68844f9dd316e7b98533fa3f2a91d29f84d425c88d6b4eff727df66a7c0197",
      ],
      [
        "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
        "a1aa0689d0fafa2ddc22e88b49133a06",
        "3843045583aac6c8c8d9128573e7a9809afb2a0f34ccc36ea9e72f16f6368e3f",
        "d034a7950cf722021ba4b84df769a5de2060e259df4c9bb4a4268c0e935bbc7470a969c9d072a1ac",
      ],
      [
        "1234567890".repeat(8),
        "3f45ef194732c2dbb2c4a2c769795fa3",
        "06fdcc7a409548aaf91368c06a6275b553e3f099bf0ea4edfd6778df89a890dd",
        "557888af5f6d8ed62ab66945c6d2a0a47ecd5341e915eb8fea1d0524955f825dc717e4a008ab2d42",
      ],
      [
        "a".repeat(1_000_000),
        "4a7f5723f954eba1216c9d8f6320431f",
        "ac953744e10e31514c150d4d8d7b677342e33399788296e43ae4850ce4f97978",
        "bdee37f4371e20646b8b0d862dda16292ae36f40965e8c8509e63d1dbddecc503e2b63eb9245bb66",
      ],
    ] as const;
    for (const [input, r128, r256, r320] of vectors) {
      expect(create("ripemd128").hash(input).digest).toBe(r128);
      expect(create("ripemd256").hash(input).digest).toBe(r256);
      expect(create("ripemd320").hash(input).digest).toBe(r320);
    }
  });

  it("ripemd128 keys HMAC as RFC 2286 test case 2 does", () => {
    expect(create("ripemd128").hash("what do ya want for nothing?", { key: "Jefe" }).digest).toBe(
      "875f828862b6b334b427c55f9f7ff09b",
    );
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

  it("derive EVP_BytesToKey over an exported hasher as OpenSSL does", () => {
    const hashers = {
      md5: () => new Md5Hasher(),
      sha1: () => new Sha1Hasher(),
      sha256: () => new Sha256Hasher(),
    };
    /** `openssl enc -aes-256-cbc -P -pass pass:password -S 0102030405060708 -md <digest>`. */
    const vectors = {
      md5: "e7b0971e52ca5cc8d0539fb3412f6316f7ba2e6ee293d9f3457b99436b51ce028d450e2ed75a84a923d4eac9fe49226b",
      sha1: "37ebd7b0dda7cbc993a9de9962e1dc2551ef134d19e96e7ce1fa3eadb854dcb504bc65de80fed6862403ff9fbb0c2f43",
      sha256:
        "2435177f1410536baad2acc155c0f94783d58384573cb0f72157443606285d3ff96efc044e0f1613bf324245c95e7411",
    };
    const password = new TextEncoder().encode("password");
    const salt = Uint8Array.fromHex("0102030405060708");
    for (const [name, create] of Object.entries(hashers)) {
      expect(evpBytesToKey(create, password, salt, 1, 48).toHex(), name).toBe(
        vectors[name as keyof typeof vectors],
      );
    }
  });

  it("derive EVP_BytesToKey like a loop over Node's digests for any salt, cost and length", () => {
    /* Each block is the digest of the last block, the password and the salt, rehashed per pass. */
    function nodeEvp(
      name: string,
      password: Uint8Array,
      salt: Uint8Array,
      passes: number,
      length: number,
    ) {
      const out: number[] = [];
      let block = Buffer.alloc(0);
      while (out.length < length) {
        block = createHash(name).update(block).update(password).update(salt).digest();
        for (let i = 1; i < passes; i++) block = createHash(name).update(block).digest();
        out.push(...block);
      }
      return Buffer.from(out.slice(0, length)).toString("hex");
    }
    const hashers = {
      md5: () => new Md5Hasher(),
      sha1: () => new Sha1Hasher(),
      sha256: () => new Sha256Hasher(),
    };
    const password = new TextEncoder().encode("correct horse");
    for (const [name, create] of Object.entries(hashers)) {
      for (const salt of [
        new Uint8Array(0),
        new Uint8Array(8).fill(7),
        new Uint8Array(13).fill(9),
      ]) {
        for (const passes of [1, 3]) {
          for (const length of [1, 16, 31, 32, 33, 100]) {
            expect(evpBytesToKey(create, password, salt, passes, length).toHex()).toBe(
              nodeEvp(name, password, salt, passes, length),
            );
          }
        }
      }
    }
  });

  it("refuse EVP_BytesToKey costs and lengths that are not positive integers", () => {
    const derive = (iterations: number, length: number) =>
      evpBytesToKey(
        () => new Md5Hasher(),
        new Uint8Array(1),
        new Uint8Array(0),
        iterations,
        length,
      );
    for (const bad of [0, -1, 1.5, Number.NaN, Number.POSITIVE_INFINITY]) {
      expect(() => derive(bad, 32)).toThrow(`Invalid option iterations=${bad}`);
      expect(() => derive(1, bad)).toThrow(`Invalid option length=${bad}`);
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
    expect(() =>
      evpBytesToKey(() => new Md5Hasher(), loose("password"), new Uint8Array(0), 1, 32),
    ).toThrow(new HashError("password must be a Uint8Array, not string"));
    expect(() => scrypt(new Uint8Array(1), loose("salt"), 16, 1, 1, 32)).toThrow(
      new HashError("salt must be a Uint8Array, not string"),
    );
  });

  it("build each SHA-2 length from its own initial value, nothing in between", () => {
    const bytes = new Uint8Array([1, 2, 3]);
    for (const [hasher, name] of [
      [new Sha224Hasher(), "sha224"],
      [new Sha512Hasher(48), "sha384"],
      [new Sha512tHasher(32), "sha512-256"],
      [new Sha512tHasher(28), "sha512-224"],
    ] as const) {
      expect(hasher.update(bytes).digest().toHex()).toBe(
        createHash(name).update(bytes).digest("hex"),
      );
    }
    for (const length of [32, 0, Number.NaN]) {
      expect(() => new Sha512Hasher(length as 64)).toThrow(InvalidOptionError);
    }
    for (const length of [48, 64, 0, Number.NaN]) {
      expect(() => new Sha512tHasher(length as 32)).toThrow(InvalidOptionError);
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

  it("derive scrypt bytes as RFC 7914 and Node do", () => {
    const text = (value: string) => new TextEncoder().encode(value);
    expect(scrypt(new Uint8Array(0), new Uint8Array(0), 16, 1, 1, 64).toHex()).toBe(
      "77d6576238657b203b19ca42c18a0497f16b4844e3074ae8dfdffa3fede21442fcd0069ded0948f8326a753a0fc81f17e8d3e0fb2e0d3628cf35e20c38d18906",
    );
    for (const [N, r, p, keyLength] of [
      [1024, 8, 16, 64],
      [2, 1, 1, 16],
      [16, 3, 2, 33],
    ] as const) {
      expect(scrypt(text("password"), text("NaCl"), N, r, p, keyLength)).toEqual(
        new Uint8Array(scryptSync("password", "NaCl", keyLength, { N, r, p })),
      );
    }
  });

  it("refuse scrypt costs that RFC 7914 rules out before any work", () => {
    const derive = (N: number, r: number, p: number, keyLength: number) => () =>
      scrypt(new Uint8Array(1), new Uint8Array(1), N, r, p, keyLength);
    for (const N of [0, 1, 3, 1000, 1.5, Number.NaN]) {
      expect(derive(N, 8, 1, 32)).toThrow(`Invalid option N=${N}`);
    }
    for (const bad of [0, -1, 1.5, Number.NaN, 2 ** 31]) {
      expect(derive(16, bad, 1, 32)).toThrow(`Invalid option r=${bad}`);
      expect(derive(16, 8, bad, 32)).toThrow(`Invalid option p=${bad}`);
      expect(derive(16, 8, 1, bad)).toThrow(`Invalid option keyLength=${bad}`);
    }
    expect(derive(65536, 1, 1, 32)).toThrow("Invalid option N=65536");
    expect(derive(2, 1, 2 ** 24, 32)).toThrow("Invalid option p=16777216");
  });

  it("derive Argon2 bytes as RFC 9106 and Node do, past 128 blocks a lane and 64 bytes out", () => {
    const rfc = {
      memory: 32,
      iterations: 3,
      parallelism: 4,
      keyLength: 32,
      secret: new Uint8Array(8).fill(3),
      associatedData: new Uint8Array(12).fill(4),
    };
    const password = new Uint8Array(32).fill(1);
    const salt = new Uint8Array(16).fill(2);
    expect(argon2d(password, salt, rfc).toHex()).toBe(
      "512b391b6f1162975371d30919734294f868e3be3984f3c1a13a4db9fabe4acb",
    );
    expect(argon2i(password, salt, rfc).toHex()).toBe(
      "c814d9d1dc7f37aa13f0d77f2494bda1c8de6b016dd388d29952a4c4672b6ce8",
    );
    expect(argon2id(password, salt, rfc).toHex()).toBe(
      "0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659",
    );
    for (const [memory, iterations, parallelism, keyLength] of [
      [1100, 2, 1, 16],
      [77, 1, 3, 65],
      [16, 3, 2, 200],
    ] as const) {
      for (const [name, derive] of [
        ["argon2d", argon2d],
        ["argon2i", argon2i],
        ["argon2id", argon2id],
      ] as const) {
        const message = new TextEncoder().encode(name);
        const nonce = new Uint8Array(9).fill(memory & 0xff);
        expect(
          derive(message, nonce, { memory, iterations, parallelism, keyLength }),
          `${name} m=${memory}`,
        ).toEqual(
          new Uint8Array(
            argon2Sync(name, {
              message,
              nonce,
              memory,
              passes: iterations,
              parallelism,
              tagLength: keyLength,
            }),
          ),
        );
      }
    }
  });

  it("refuse Argon2 parameters that RFC 9106 rules out before any work", () => {
    const derive =
      (parameters: object, salt = new Uint8Array(8)) =>
      () =>
        argon2id(new Uint8Array(1), salt, {
          memory: 8,
          iterations: 1,
          parallelism: 1,
          keyLength: 4,
          ...parameters,
        });
    for (const bad of [0, -1, 1.5, Number.NaN, 2 ** 32]) {
      expect(derive({ iterations: bad })).toThrow(`Invalid option iterations=${bad}`);
      expect(derive({ parallelism: bad })).toThrow(`Invalid option parallelism=${bad}`);
      expect(derive({ memory: bad })).toThrow(`Invalid option memory=${bad}`);
      expect(derive({ keyLength: bad })).toThrow(`Invalid option keyLength=${bad}`);
    }
    expect(derive({ keyLength: 3 })).toThrow("Invalid option keyLength=3");
    expect(derive({ parallelism: 2 ** 24 })).toThrow("Invalid option parallelism=16777216");
    expect(derive({ memory: 15, parallelism: 2 })).toThrow("Invalid option memory=15");
    expect(derive({}, new Uint8Array(7))).toThrow("Invalid option salt=7 bytes");
    expect(derive({ secret: "00" })).toThrow(
      new HashError("secret must be a Uint8Array, not string"),
    );
    const loose = (value: unknown) => value as Parameters<typeof argon2id>[2];
    expect(() => argon2id(new Uint8Array(1), new Uint8Array(8), loose(null))).toThrow(
      "Invalid option parameters=null",
    );
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
    sha1: ["Sha1Hasher", "sha1"],
    md5: ["Md5Hasher", "md5"],
    sha2: ["Sha256Hasher", "Sha512Hasher", "hash256", "sha256", "sha512"],
    ripemd160: ["Ripemd160Hasher", "hash160", "ripemd160"],
    keccak: ["keccak256", "sha3_256"],
    blake2b: ["Blake2bHasher", "blake2b"],
    blake256: ["blake256"],
    crc: ["crc16Xmodem", "crc32"],
    hmac: ["hkdf", "hkdfExpand", "hkdfExtract", "hmac", "pbkdf2"],
    evp: ["evpBytesToKey"],
    scrypt: ["scrypt"],
    argon2: ["argon2d", "argon2i", "argon2id"],
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
      const kdf = create(name).info().category === "password" || name === "hkdf";
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

  it("derives OpenSSL's key and IV with EVP_BytesToKey for each digest", () => {
    /** `openssl enc -aes-256-cbc -P -pass pass:password -S 0102030405060708 -md <digest>`. */
    const vectors = {
      md5: "e7b0971e52ca5cc8d0539fb3412f6316f7ba2e6ee293d9f3457b99436b51ce028d450e2ed75a84a923d4eac9fe49226b",
      sha1: "37ebd7b0dda7cbc993a9de9962e1dc2551ef134d19e96e7ce1fa3eadb854dcb504bc65de80fed6862403ff9fbb0c2f43",
      sha256:
        "2435177f1410536baad2acc155c0f94783d58384573cb0f72157443606285d3ff96efc044e0f1613bf324245c95e7411",
    };
    const evp = create("evp-bytestokey");
    for (const [digest, expected] of Object.entries(vectors)) {
      const result = evp.hash("password", {
        digest,
        salt: "0102030405060708",
      } as EvpBytesToKeyOptions);
      expect(result.digest, digest).toBe(expected);
      expect(result.options).toEqual({
        encoding: "hex",
        digest,
        iterations: 1,
        keyLength: 32,
        ivLength: 16,
        salt: "0102030405060708",
      });
    }
    /** `openssl enc -aes-128-cbc -P -pass pass:password -nosalt -md md5`. */
    expect(evp.hash("password", { keyLength: 16 } as EvpBytesToKeyOptions).digest).toBe(
      "5f4dcc3b5aa765d61d8327deb882cf992b95990a9151374abd8ff8c5a7a0fe08",
    );
    /** `openssl enc -des-cbc -P -pass pass:secret -S a1b2c3d4e5f60718 -md sha256`. */
    const des = { digest: "sha256", salt: "a1b2c3d4e5f60718", keyLength: 8, ivLength: 8 };
    expect(evp.hash("secret", des as EvpBytesToKeyOptions).digest).toBe(
      "a7e68756e88549d2d7d6a267f1379051",
    );
  });

  it("derives CryptoJS EvpKDF output past one key and past one iteration", () => {
    const evp = create("evp-bytestokey");
    const salt = "0102030405060708";
    /** crypto-js 4.2.0: `EvpKDF.create({ keySize: 36 }).compute("password", salt)`. */
    expect(evp.hash("password", { salt, keyLength: 128 } as EvpBytesToKeyOptions).digest).toBe(
      "e7b0971e52ca5cc8d0539fb3412f6316f7ba2e6ee293d9f3457b99436b51ce028d450e2ed75a84a923d4eac9fe49226b19ebc118602201f8c0d0798d321aa279b0cccbdb6f705ffa4b672aa277fc5ea66a5dd99cedc46e0a697eccb3fa3c9176e97d1daa8f75383e402073799c137f7683d06d0838314ba64b3d2576b449433021edd225540e98ba10a6f00cd679611b",
    );
    /** crypto-js 4.2.0: `EvpKDF.create({ keySize: 12, iterations: 1000 })` over the same input. */
    expect(evp.hash("password", { salt, iterations: 1000 } as EvpBytesToKeyOptions).digest).toBe(
      "2699a412f542751988e26bb58932380585bb8c6bfa9bf3745af25d787fe80d519d89aec48c5a6e415bfd5112f3c8abbb",
    );
    expect(evp.hash("password", { salt, ivLength: 0 } as EvpBytesToKeyOptions).digest).toBe(
      "e7b0971e52ca5cc8d0539fb3412f6316f7ba2e6ee293d9f3457b99436b51ce02",
    );
  });

  it("refuses an EVP_BytesToKey salt that is not 8 bytes and a hash OpenSSL enc does not take", () => {
    const evp = create("evp-bytestokey");
    const derive = (options: Readonly<EvpBytesToKeyOptions>) => () => evp.hash("x", options);
    expect(derive({ salt: "01020304" })).toThrow("Invalid option salt=01020304: must be 8 bytes");
    expect(derive({ digest: "sha512" })).toThrow(
      "Invalid option digest=sha512: use one of md5, sha1, sha256",
    );
    expect(derive({ digest: "constructor" })).toThrow("Invalid option digest=constructor");
    for (const ivLength of [-1, 1.5, Number.NaN]) {
      expect(derive({ ivLength })).toThrow(`Invalid option ivLength=${ivLength}`);
    }
    for (const value of [0, -1, 1.5]) {
      expect(derive({ keyLength: value })).toThrow(`Invalid option keyLength=${value}`);
      expect(derive({ iterations: value })).toThrow(`Invalid option iterations=${value}`);
    }
    expect(derive({ rounds: 2 })).toThrow(HashError);
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

  it("matches Node's Argon2 and reports the salt and cost, never the secret", () => {
    for (const name of ["argon2id", "argon2i", "argon2d"] as const) {
      const result = create(name).hash("password", {
        salt,
        memory: 64,
        iterations: 2,
        parallelism: 2,
        secret: "0102",
        associatedData: "ff",
      } as Argon2Options);
      expect(result.digest).toBe(
        argon2Sync(name, {
          message: "password",
          nonce: Buffer.from(salt, "hex"),
          memory: 64,
          passes: 2,
          parallelism: 2,
          tagLength: 32,
          secret: Buffer.from("0102", "hex"),
          associatedData: Buffer.from("ff", "hex"),
        }).toString("hex"),
      );
      expect(result.options).toEqual({
        encoding: "hex",
        memory: 64,
        iterations: 2,
        parallelism: 2,
        keyLength: 32,
        associatedData: "ff",
        salt,
      });
    }
  });

  it("draws an Argon2 salt that verify then needs", () => {
    const argon2 = create("argon2id");
    const cost = { memory: 8, iterations: 1, parallelism: 1 } as Argon2Options;
    const result = argon2.hash("pw", cost);
    expect(String(result.options["salt"])).toMatch(/^[0-9a-f]{64}$/);
    expect(argon2.info().options.find((option) => option.name === "salt")?.random).toBe(true);
    expect(() => argon2.hash("pw", { ...cost, salt: "00" } as Argon2Options)).toThrow(
      "Invalid option salt=1 bytes",
    );
    expect(() => argon2.hash("pw", { ...cost, secret: "abc" } as Argon2Options)).toThrow(
      InvalidOptionError,
    );
    expect(() => argon2.hash("pw", { ...cost, salt, rounds: 2 } as Argon2Options)).toThrow(
      "argon2id sets its cost with its own parameters",
    );
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

describe("extendDigest", () => {
  const text = (value: string) => new TextEncoder().encode(value);
  const node = new Set(["md5", "sha1", "sha256", "sha512", "ripemd160"]);

  it("forges the digest from the issue without the secret", () => {
    const forged = extendDigest({
      algorithm: "sha256",
      digest: Uint8Array.fromHex(
        "ca2c6fe0b879f58a8afea413fef7202c94a5156ccfb5d22c4ef690af5117a081",
      ),
      message: text("data"),
      secretLength: 6,
      suffix: text("append"),
    });

    expect(forged.digest.toHex()).toBe(
      "5e6f4311f409a57a899e8e36fc5c9d27bc5fd5d5f797ad693004d34815a81214",
    );
    expect(forged.padding.toHex()).toBe(`80${"00".repeat(45)}0000000000000050`);
    expect(forged.message.toHex()).toBe(
      `${text("data").toHex()}${forged.padding.toHex()}${text("append").toHex()}`,
    );
  });

  it("lists the Merkle-Damgard hashes whose digest is the whole state", () => {
    expect(extendableAlgorithms()).toEqual([
      "sha256",
      "sha512",
      "ripemd160",
      "ripemd320",
      "md5",
      "md4",
      "sha1",
      "sha0",
      "ripemd128",
      "ripemd256",
    ]);
  });

  it.each([
    "sha256",
    "sha512",
    "ripemd160",
    "ripemd320",
    "md5",
    "md4",
    "sha1",
    "sha0",
    "ripemd128",
    "ripemd256",
  ])("%s matches the hash of the secret and the forged message at every block offset", (name) => {
    const algorithm = create(name);
    const hash = (bytes: Uint8Array) => algorithm.hash(bytes).digest as string;
    for (let prefix = 0; prefix <= 260; prefix += 7) {
      for (const suffixLength of [0, 1, 55, 64, 129]) {
        const secretLength = prefix % 19;
        const secret = Uint8Array.from({ length: secretLength }, (_, i) => i + 1);
        const message = Uint8Array.from({ length: prefix - secretLength }, (_, i) => i ^ 0x5a);
        const suffix = Uint8Array.from({ length: suffixLength }, (_, i) => 255 - i);
        const known = new Uint8Array([...secret, ...message]);
        const forged = extendDigest({
          algorithm: name,
          digest: Uint8Array.fromHex(hash(known)),
          message,
          secretLength,
          suffix,
        });
        const full = new Uint8Array([...secret, ...forged.message]);

        expect(forged.digest.toHex()).toBe(hash(full));
        if (node.has(name)) {
          expect(forged.digest.toHex()).toBe(createHash(name).update(full).digest("hex"));
        }
      }
    }
  });

  it.each([
    "sha224",
    "sha384",
    "sha512-224",
    "sha512-256",
    "sha512-half",
    "sha3-256",
    "ntlm",
    "hash160",
  ])("refuses %s, whose digest is not a state it can resume from", (algorithm) => {
    const call = () =>
      extendDigest({
        algorithm,
        digest: new Uint8Array(32),
        message: new Uint8Array(),
        secretLength: 1,
        suffix: new Uint8Array(),
      });

    expect(call).toThrow(InvalidOptionError);
    expect(call).toThrow("cannot be extended, use one of sha256, sha512");
  });

  it("refuses a digest of the wrong length, a bad secret length and anything but bytes", () => {
    const base = {
      algorithm: "md5",
      digest: new Uint8Array(16),
      message: new Uint8Array(),
      secretLength: 4,
      suffix: new Uint8Array(),
    };

    expect(() => extendDigest({ ...base, digest: new Uint8Array(20) })).toThrow(
      "md5 digests are 16 bytes",
    );
    for (const secretLength of [-1, 1.5, Number.NaN, 2 ** 53]) {
      expect(() => extendDigest({ ...base, secretLength })).toThrow(InvalidOptionError);
    }
    for (const key of ["digest", "message", "suffix"] as const) {
      expect(() => extendDigest({ ...base, [key]: "abc" as unknown as Uint8Array })).toThrow(
        `${key} must be a Uint8Array`,
      );
    }
  });

  it("lets a hasher resume only from a whole state on a block boundary", () => {
    expect(() => new Sha256Hasher().resume(new Uint8Array(31), 64)).toThrow(HashError);
    expect(() => new Sha256Hasher().resume(new Uint8Array(32), 63)).toThrow(HashError);
    expect(() => new Sha256Hasher().resume(new Uint8Array(32), Number.NaN)).toThrow(HashError);
    expect(() => new Sha224Hasher().resume(new Uint8Array(28), 64)).toThrow(HashError);
    expect(() => new Sha256Hasher().resume("x".repeat(32) as unknown as Uint8Array, 64)).toThrow(
      "digest must be a Uint8Array",
    );
  });
});

describe("identifyDigest", () => {
  /** `password` as mkpasswd, openssl passwd, htpasswd, argon2, passlib and Django wrote it. */
  const FORMATS: readonly (readonly [string, string, string | undefined])[] = [
    ["$2b$05$QsIsJOmzLmIuvm2cp78uNewLvFwT6DZugTSNTOPcOuByusi7cqLHy", "bcrypt", undefined],
    ["$2y$10$ohjdIMwX4ixMxLrzKd3ruuMwvA1nrvwq5Fg7NGIxz7jR3vsgR93wa", "bcrypt", undefined],
    [
      "$6$saltsalt$qFmFH.bQmmtXzyBY0s9v7Oicd2z4XSIecDzlB5KiA2/jctKu9YterLp8wwnSq.qc.eoxqOmSuNp2xS0ktL3nh/",
      "sha512crypt",
      undefined,
    ],
    ["$5$saltsalt$gOjOtoMpVhru2uyjeJSEc/JaLQWOXMNmlOnj6T4AtC.", "sha256crypt", undefined],
    ["$1$saltsalt$qjXMvbEw8oaL.CzflDtaK/", "md5crypt", undefined],
    ["$apr1$saltsalt$yAAkm4libquA.ZWLHbSBq/", "apr1", undefined],
    [
      "$y$j9T$SvJBRoE0tLcBbw6qYN7MW/$yz2D1Q1DrXJRuWn9pNp.BYmXW7f//xLYS0HAxdTklDD",
      "yescrypt",
      undefined,
    ],
    [
      "$7$CU..../....6C.kkSqZ9FAxB678v8JRN1$qC9lVMZO0da0sYoJTQxB6OdqgtB6ihPGgjCMzm8a4H5",
      "scrypt-crypt",
      undefined,
    ],
    [
      "$argon2id$v=19$m=1024,t=2,p=2$c29tZXNhbHRzYWx0$8mkYn4qtK5HHJtQQI+FNQKE4UECfkb5diD560/y7mZs",
      "argon2id",
      "argon2id",
    ],
    [
      "$scrypt$ln=10,r=8,p=1$c2FsdHNhbHQ$AOLXEESCcPmf2DxU3D47ZJxp5ZTcHC0S2Mb2eFXc4tI",
      "scrypt",
      "scrypt",
    ],
    [
      "$pbkdf2-sha256$1000$c2FsdHNhbHQ$E196ZhRPzw.wA84EjzHwJO1cv/MFJdO6C/sxmUeTYqY",
      "pbkdf2-sha256",
      "pbkdf2",
    ],
    [
      "$pbkdf2-sha512$1000$c2FsdHNhbHQ$Q6v4xwJ8a9nWPp2BeEoAYYhHSo2xRmPWART17vTpSxt2q6iNp7BOozW557qqa95eNjUO4gKs0CyvJbYGGku1tA",
      "pbkdf2-sha512",
      "pbkdf2",
    ],
    ["$pbkdf2$1000$c2FsdHNhbHQ$6f6/9Uv85mj94wGsyFVjzJ3HHvY", "pbkdf2-sha1", undefined],
    [
      "pbkdf2_sha256$1000$saltsalt$E196ZhRPzw+wA84EjzHwJO1cv/MFJdO6C/sxmUeTYqY=",
      "django-pbkdf2",
      "pbkdf2",
    ],
    ["*2470C0C06DEE42FD1618BB99005ADCA2EC9D1E19", "mysql41", "sha1"],
  ];

  it.each(FORMATS)("names %s by its prefix", (text, name, algorithm) => {
    const found = identifyDigest(`  ${text}\n`);

    expect(found.reading).toBe("format");
    expect(found.candidates).toHaveLength(1);
    expect(found.candidates[0]).toMatchObject({ name, fit: "format" });
    expect(found.candidates[0]!.algorithm).toBe(algorithm);
  });

  it.each(FORMATS.filter(([, , algorithm]) => algorithm !== undefined))(
    "reads the salt, costs and digest out of %s so hashing the password matches",
    (text) => {
      const [candidate] = identifyDigest(text).candidates;
      const { algorithm, expected, parameters, salt } = candidate!;
      const result = create(algorithm!).hash("password", {
        ...parameters,
        ...(salt === undefined ? {} : { salt: Uint8Array.fromHex(salt) }),
      } as HashOptions);

      expect(result.digest).toBe(expected);
    },
  );

  it("reads MySQL 4.1 as SHA-1 over the SHA-1 bytes", () => {
    const inner = createHash("sha1").update("password").digest();
    const mysql = `*${createHash("sha1").update(inner).digest("hex").toUpperCase()}`;

    expect(identifyDigest(mysql).candidates[0]).toMatchObject({
      algorithm: "sha1",
      parameters: { rounds: 2 },
      expected: createHash("sha1").update(inner).digest("hex"),
    });
  });

  it("keeps a format this package cannot compute without the call", () => {
    const [bcrypt] = identifyDigest(FORMATS[0]![0]).candidates;
    const [sha1] = identifyDigest(
      "$pbkdf2$1000$c2FsdHNhbHQ$6f6/9Uv85mj94wGsyFVjzJ3HHvY",
    ).candidates;
    const legacy =
      "$argon2i$v=16$m=65536,t=2,p=1$c29tZXNhbHQ$9sTbSlTio3Biev89thdrlKKiCaYsjjYVJxGAL3swxpQ";
    const [old] = identifyDigest(legacy).candidates;

    expect(bcrypt).toEqual({ name: "bcrypt", label: "bcrypt", fit: "format", note: "cost 5" });
    expect(sha1!.algorithm).toBeUndefined();
    expect(sha1!.note).toContain("over sha1, while pbkdf2 here takes sha256");
    expect(old).toMatchObject({
      name: "argon2i",
      fit: "format",
      note: "version 16, while this package runs 19",
    });
    expect(old!.algorithm).toBeUndefined();
    expect(identifyDigest(legacy.replace("v=16$", "")).candidates[0]!.note).toBe(old!.note);
  });

  it.each([
    "$pbkdf2-sha256$1000$A$E196ZhRPzw.wA84EjzHwJO1cv/MFJdO6C/sxmUeTYqY",
    "$argon2id$v=19$m=1,t=1,p=1$A$c29tZXNhbHQ",
  ])("takes %s, whose salt is not base64, for its prefix alone", (text) => {
    expect(identifyDigest(text).candidates[0]!.fit).toBe("prefix");
  });

  it("takes a cost past ten digits for a broken layout, not Infinity", () => {
    const huge = `$argon2id$v=19$m=${"9".repeat(400)},t=2,p=2$c29tZXNhbHQ$c29tZXNhbHQ`;

    expect(identifyDigest(huge).candidates).toEqual([
      { name: "argon2id", label: "Argon2id, PHC string", fit: "prefix" },
    ]);
  });

  it("names a format by its prefix when the rest does not fit", () => {
    expect(identifyDigest("$2b$05$truncated").candidates).toEqual([
      { name: "bcrypt", label: "bcrypt", fit: "prefix" },
    ]);
    expect(identifyDigest("$argon2id$v=19$m=1024").candidates[0]).toEqual({
      name: "argon2id",
      label: "Argon2id, PHC string",
      fit: "prefix",
    });
  });

  it("lists the fixed digests of that length, then those this package lacks, then the KDFs", () => {
    const md5 = createHash("md5").update("hello").digest();
    const found = identifyDigest(md5.toString("hex").toUpperCase());

    expect(found).toMatchObject({ reading: "hex", length: 16, hex: md5.toString("hex") });
    expect(
      found.candidates.map((candidate) => [candidate.name, candidate.fit, candidate.algorithm]),
    ).toEqual([
      ["md5", "length", "md5"],
      ["md4", "length", "md4"],
      ["ntlm", "length", "ntlm"],
      ["ripemd128", "length", "ripemd128"],
      ["md2", "length", undefined],
      ["lm", "length", undefined],
      ...["scrypt", "pbkdf2", "hkdf", "evp-bytestokey", "argon2id", "argon2i", "argon2d"].map(
        (name) => [name, "keyLength", name],
      ),
    ]);
    expect(found.candidates.at(-1)!.parameters).toEqual({ keyLength: 16 });
  });

  it("reads base64 in either alphabet, padded or not, after hex fails", () => {
    const digest = createHash("sha256").update("abc").digest();
    for (const text of [digest.toString("base64"), digest.toString("base64url")]) {
      expect(identifyDigest(text)).toMatchObject({
        reading: "base64",
        length: 32,
        hex: digest.toString("hex"),
      });
    }
    expect(identifyDigest(digest.toString("base64").replace(/=+$/, "")).length).toBe(32);
  });

  it("puts keccak256 first after 0x and leaves KDFs out below 16 bytes", () => {
    const prefixed = identifyDigest(`0x${"ab".repeat(32)}`);
    const crc = identifyDigest("cbf43926");

    expect(prefixed.candidates[0]).toMatchObject({
      name: "keccak256",
      note: "0x is how Ethereum writes Keccak-256",
    });
    expect(prefixed.candidates[1]!.name).toBe("sha256");
    expect(identifyDigest("ab".repeat(32)).candidates[0]!.name).toBe("sha256");
    expect(crc.candidates.map((candidate) => candidate.name)).toEqual([
      "crc32",
      "adler32",
      "crc32c",
    ]);
  });

  it("counts a registered algorithm as computable in place of the one it replaces", () => {
    class Sha3_384 extends FixedHash {
      static readonly key = "sha3-384";
      protected readonly about = {
        label: "SHA3-384",
        description: "SHA-3 family 384-bit hash",
        family: "SHA",
        category: "cryptographic",
        digestLength: 48,
      } as const;

      protected digest(bytes: Uint8Array): Uint8Array {
        return createHash("sha3-384").update(bytes).digest();
      }
    }
    register(Sha3_384);

    const names = identifyDigest("00".repeat(48)).candidates.filter(
      (candidate) => candidate.fit === "length",
    );
    expect(names.map((candidate) => [candidate.name, candidate.algorithm])).toEqual([
      ["sha384", "sha384"],
      ["sha3-384", "sha3-384"],
    ]);
  });

  it.each([
    ["abc", "an odd number of hex digits"],
    ["$zz$abc$def", "a $ prefix no known format uses"],
    ["$zz\nmd5: MD5, computable", "a $ prefix no known format uses"],
    ["hello world", "neither hex, base64 nor a known format"],
    ["00".repeat(7), "nothing known here makes 7 bytes"],
  ])("finds no candidate for %j", (text, note) => {
    expect(identifyDigest(text)).toMatchObject({ candidates: [], note });
  });

  it("refuses an empty string and anything but a string", () => {
    expect(() => identifyDigest(" \n")).toThrow("Invalid option digest=(empty): must not be empty");
    expect(() => identifyDigest(new Uint8Array(16) as unknown as string)).toThrow(
      "Invalid option digest=object: must be a string",
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
      const argon2 = { memory: 8, iterations: 1, parallelism: 1 };
      const costs = {
        scrypt: { N: 16 },
        pbkdf2: { iterations: 1 },
        argon2id: argon2,
        argon2i: argon2,
        argon2d: argon2,
      };
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
