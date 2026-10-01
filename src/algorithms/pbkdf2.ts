import {
  assertOneRound,
  ENCODING_OPTION,
  assertPositiveIntegers,
  SALT_OPTION,
  encodeDigest,
  guarded,
  resolveSalt,
  toBytes,
  type SaltOptions,
} from "../core/digest.ts";
import { InvalidOptionError } from "../core/errors.ts";
import { Hash } from "../core/hash.ts";
import type { BlockHash } from "../core/block-hash.ts";
import { pbkdf2 } from "../core/hmac.ts";
import type { AlgorithmInfo, HashInput, HashOptions, HashResult } from "../core/types.ts";
import { Sha256 } from "./sha256.ts";
import { Sha3_256 } from "./sha3-256.ts";
import { Sha3_512 } from "./sha3-512.ts";
import { Sha384 } from "./sha384.ts";
import { Sha512 } from "./sha512.ts";

/** Hashes PBKDF2 and HKDF run HMAC over, by their registry names. */
const HASHES: Readonly<Record<string, new () => BlockHash>> = {
  sha256: Sha256,
  sha384: Sha384,
  sha512: Sha512,
  "sha3-256": Sha3_256,
  "sha3-512": Sha3_512,
};

/**
 * Lists the hashes PBKDF2 and HKDF take. A module-level list would keep every class in `HASHES`
 * in a bundle that never touches a KDF, since esbuild cannot drop the call that builds it.
 *
 * @returns {string} Their names, comma-separated.
 */
export function kdfDigests(): string {
  return Object.keys(HASHES).join(", ");
}

/**
 * Creates the hash a KDF runs HMAC over, refusing weaker ones such as `md5`.
 *
 * @param digest - Its registry name.
 * @returns {BlockHash} The hash.
 */
export function kdfHash(digest: string): BlockHash {
  if (!Object.hasOwn(HASHES, digest)) {
    throw new InvalidOptionError("digest", digest, `use one of ${kdfDigests()}`);
  }
  return new HASHES[digest]!();
}

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
 * Reads the PBKDF2 options with their defaults.
 *
 * @param options - The PBKDF2 options.
 * @returns {{ iterations: number, digest: string, hash: BlockHash, keyLength: number }} The parameters.
 */
function parameters(options?: Readonly<Pbkdf2Options>) {
  const { iterations = 600_000, digest = "sha512", keyLength = 64 } = options ?? {};
  assertPositiveIntegers({ iterations, keyLength });
  return { iterations, digest, hash: kdfHash(digest), keyLength };
}

export class Pbkdf2 extends Hash {
  static readonly key = "pbkdf2";

  /**
   * Describes the algorithm.
   *
   * @returns {AlgorithmInfo} Its metadata.
   */
  info(): AlgorithmInfo {
    return {
      name: this.key,
      label: "PBKDF2",
      description: "PBKDF2 password-based KDF, the NIST standard with configurable iterations",
      family: "PBKDF",
      category: "password",
      hmac: false,
      options: [
        ENCODING_OPTION,
        SALT_OPTION,
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
          description: `Underlying hash: ${kdfDigests()}`,
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
    };
  }

  /**
   * Derives a key from the input.
   *
   * @param input - Text or bytes.
   * @param options - Encoding, salt and cost parameters.
   * @returns {HashResult} The derived key.
   */
  hash(input: HashInput, options?: Readonly<Pbkdf2Options>): HashResult {
    return guarded(this.key, () => {
      if (options?.key !== undefined) throw new Error(`${this.key} has no HMAC mode`);
      assertOneRound(options, `${this.key} sets its cost with its own parameters`);
      const { iterations, digest, hash, keyLength } = parameters(options);
      const salt = resolveSalt(options);
      const raw = pbkdf2(() => hash.hasher(), toBytes(input), salt, iterations, keyLength);
      return encodeDigest(raw, this.key, "hash", options?.encoding ?? "hex", {
        iterations,
        digest,
        keyLength,
        salt: salt.toHex(),
      });
    });
  }
}
