import { randomBytes } from "node:crypto";
import { InvalidOptionError, normalizeError } from "./errors.ts";
import type { HashInput, HashResult, OutputEncoding } from "./types.ts";

/**
 * Reads the input as bytes: a string as UTF-8, bytes as they are.
 *
 * @param input - Text or bytes.
 * @returns {Uint8Array} The input's bytes.
 */
export function toBytes(input: HashInput): Uint8Array {
  return typeof input === "string" ? new TextEncoder().encode(input) : input;
}

/**
 * Encodes a raw digest into the result shape every algorithm returns.
 *
 * @param raw - Raw digest bytes.
 * @param algorithm - Name of the algorithm that produced them.
 * @param operation - Whether this is a plain hash or an HMAC.
 * @param encoding - Output encoding.
 * @param extraOptions - Options the digest depends on besides the encoding.
 * @returns {HashResult} The encoded result.
 */
export function encodeDigest(
  raw: Uint8Array,
  algorithm: string,
  operation: "hash" | "hmac",
  encoding: OutputEncoding,
  extraOptions?: Readonly<Record<string, unknown>>,
): HashResult {
  const digest = encoding === "binary" ? raw : Buffer.from(raw).toString(encoding);
  return {
    digest,
    algorithm,
    operation,
    encoding,
    digestLength: raw.length,
    options: { encoding, ...extraOptions },
  };
}

/**
 * Runs a digest computation and wraps any failure in a HashError tagged with the algorithm.
 *
 * @param algorithm - Name of the algorithm, for the error.
 * @param compute - Computes the result.
 * @returns {HashResult} What `compute` returned.
 */
export function guarded(algorithm: string, compute: () => HashResult): HashResult {
  try {
    return compute();
  } catch (error) {
    throw normalizeError(error, algorithm);
  }
}

/** Salt options the KDFs share. */
export interface SaltOptions {
  /** Salt as bytes or encoded text. Default: 32 random bytes. */
  salt?: HashInput;
  /** Encoding of a string salt. Default: `hex`. */
  saltEncoding?: "hex" | "base64" | "utf8";
}

const HEX_BYTES = /^(?:[0-9a-f]{2})+$/i;

/**
 * Reads the salt option, or draws 32 random bytes without one. A hex salt that is not whole hex
 * bytes is refused: `Buffer.from` would drop the bad digits and derive with a shorter salt.
 *
 * @param options - The KDF options.
 * @returns {Uint8Array} The salt's bytes.
 */
export function resolveSalt(options?: Readonly<SaltOptions>): Uint8Array {
  const salt = options?.salt;
  if (salt === undefined) return randomBytes(32);
  if (typeof salt !== "string") return salt;
  const encoding = options?.saltEncoding ?? "hex";
  if (encoding === "hex" && !HEX_BYTES.test(salt)) {
    throw new InvalidOptionError("salt", salt, "must be whole bytes in hex");
  }
  return Buffer.from(salt, encoding);
}
