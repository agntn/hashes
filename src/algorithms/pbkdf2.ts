import { pbkdf2 as noblePbkdf2 } from "@noble/hashes/pbkdf2.js";
import { sha256, sha384, sha512 } from "@noble/hashes/sha2.js";
import { sha3_256, sha3_512 } from "@noble/hashes/sha3.js";
import type { CHash } from "@noble/hashes/utils.js";
import { encodeDigest, guarded, resolveSalt, toBytes, type SaltOptions } from "../core/digest.ts";
import { InvalidOptionError } from "../core/errors.ts";
import type { AlgorithmEntry, HashAlgorithm, HashInput, HashOptions } from "../core/types.ts";

/** Hashes PBKDF2 runs HMAC over. A null prototype, so `constructor` is no digest. */
const DIGESTS: Readonly<Record<string, CHash>> = Object.assign(Object.create(null) as object, {
  sha256,
  sha384,
  sha512,
  "sha3-256": sha3_256,
  "sha3-512": sha3_512,
});

/** Options PBKDF2 takes besides the encoding. */
export interface Pbkdf2Options extends HashOptions, SaltOptions {
  /** Iteration count. Default: 600000. */
  iterations?: number;
  /** Hash under HMAC: sha256, sha384, sha512, sha3-256, sha3-512. Default: sha512. */
  digest?: string;
  /** Output key length in bytes. Default: 64. */
  keyLength?: number;
}

/**
 * Looks up the hash PBKDF2 runs HMAC over.
 *
 * @param digest - Its name.
 * @returns {CHash} The noble hash.
 */
function digestHash(digest: string): CHash {
  const hashFn = Object.hasOwn(DIGESTS, digest) ? DIGESTS[digest] : undefined;
  if (hashFn === undefined) {
    throw new InvalidOptionError("digest", digest, `use one of ${Object.keys(DIGESTS).join(", ")}`);
  }
  return hashFn;
}

const algorithm: HashAlgorithm = {
  name: () => "pbkdf2",
  info: () => ({
    name: "pbkdf2",
    label: "PBKDF2",
    description: "PBKDF2 password-based KDF, the NIST standard with configurable iterations",
    family: "password",
    hmac: false,
    options: [
      {
        name: "encoding",
        type: "string",
        required: false,
        default: "hex",
        description: "Output encoding",
      },
      {
        name: "salt",
        type: "string",
        required: false,
        description: "Salt in hex; 32 random bytes when omitted",
      },
      {
        name: "iterations",
        type: "number",
        required: false,
        default: 600000,
        description: "Iteration count (OWASP: >=600000 with sha256, >=220000 with sha512)",
      },
      {
        name: "digest",
        type: "string",
        required: false,
        default: "sha512",
        description: `Underlying hash: ${Object.keys(DIGESTS).join(", ")}`,
      },
      {
        name: "keyLength",
        type: "number",
        required: false,
        default: 64,
        description: "Output key length in bytes",
      },
    ],
    securityNote:
      "OWASP Password Storage Cheat Sheet: >=600000 iterations with HMAC-SHA256, >=220000 with HMAC-SHA512.",
  }),
  hash: (input: HashInput, options?: Readonly<Pbkdf2Options>) =>
    guarded("pbkdf2", () => {
      const {
        iterations = 600_000,
        digest = "sha512",
        keyLength = 64,
        encoding = "hex",
      } = options ?? {};
      if (!Number.isInteger(iterations) || iterations < 1) {
        throw new InvalidOptionError("iterations", iterations, "must be an integer >= 1");
      }
      const hashFn = digestHash(digest);
      const salt = resolveSalt(options);
      const raw = noblePbkdf2(hashFn, toBytes(input), salt, { c: iterations, dkLen: keyLength });
      return encodeDigest(raw, "pbkdf2", "hash", encoding, {
        iterations,
        digest,
        keyLength,
        salt: Buffer.from(salt).toString("hex"),
      });
    }),
};

export const pbkdf2: AlgorithmEntry = { name: "pbkdf2", create: () => algorithm };
