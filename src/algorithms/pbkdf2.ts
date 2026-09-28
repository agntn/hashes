import { pbkdf2Sync } from "node:crypto";
import {
  ENCODING_OPTION,
  SALT_OPTION,
  encodeDigest,
  guarded,
  resolveSalt,
  toBytes,
  type SaltOptions,
} from "../core/digest.ts";
import { InvalidOptionError } from "../core/errors.ts";
import { Hash } from "../core/hash.ts";
import type { AlgorithmInfo, HashInput, HashOptions, HashResult } from "../core/types.ts";

/** Hashes PBKDF2 runs HMAC over, by their OpenSSL names. */
const DIGESTS: readonly string[] = ["sha256", "sha384", "sha512", "sha3-256", "sha3-512"];

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
 * Reads the PBKDF2 options with their defaults. Only the listed digests reach OpenSSL, which
 * would take weaker ones such as `md5` too.
 *
 * @param options - The PBKDF2 options.
 * @returns {{ iterations: number, digest: string, keyLength: number }} The parameters.
 */
function parameters(options?: Readonly<Pbkdf2Options>) {
  const { iterations = 600_000, digest = "sha512", keyLength = 64 } = options ?? {};
  if (!Number.isInteger(iterations) || iterations < 1) {
    throw new InvalidOptionError("iterations", iterations, "must be an integer >= 1");
  }
  if (!DIGESTS.includes(digest)) {
    throw new InvalidOptionError("digest", digest, `use one of ${DIGESTS.join(", ")}`);
  }
  return { iterations, digest, keyLength };
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
      family: "password",
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
          description: `Underlying hash: ${DIGESTS.join(", ")}`,
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
      const { iterations, digest, keyLength } = parameters(options);
      const salt = resolveSalt(options);
      const raw = pbkdf2Sync(toBytes(input), salt, iterations, keyLength, digest);
      return encodeDigest(raw, this.key, "hash", options?.encoding ?? "hex", {
        iterations,
        digest,
        keyLength,
        salt: Buffer.from(salt).toString("hex"),
      });
    });
  }
}
