import { randomBytes } from "node:crypto";
import { InvalidOptionError, normalizeError } from "./errors.ts";
import type { AlgorithmInfo, HashInput, HashOption, HashResult, OutputEncoding } from "./types.ts";

/** The `encoding` option every algorithm takes. */
export const ENCODING_OPTION: HashOption = {
  name: "encoding",
  type: "string",
  required: false,
  default: "hex",
  description: "Output encoding: hex, base64, base64url, binary",
};

/** The `salt` option of the key derivation functions. */
export const SALT_OPTION: HashOption = {
  name: "salt",
  type: "string",
  required: false,
  description: "Salt in hex; 32 random bytes when omitted",
};

/**
 * Whether the algorithm's digest depends on a salt, read from its declared options.
 *
 * @param info - The algorithm's metadata.
 * @returns {boolean} Whether it takes a `salt` option.
 */
export function takesSalt(info: AlgorithmInfo): boolean {
  return info.options.some((option) => option.name === SALT_OPTION.name);
}

/**
 * Lists what a digest depends on besides its encoding, such as a KDF's salt and cost, in the
 * `name value, name value` form the CLI and the tools print.
 *
 * @param options - The options a result reports.
 * @returns {string} The parameters, or an empty string when there are none.
 */
export function parameterText(options: Readonly<Record<string, unknown>>): string {
  return Object.entries(options)
    .filter(([name]) => name !== "encoding" && name !== "hmac")
    .map(([name, value]) => `${name} ${String(value)}`)
    .join(", ");
}

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
  // A plain Uint8Array over the same bytes: node:crypto hands out Buffers, the contract says bytes.
  const digest =
    encoding === "binary"
      ? new Uint8Array(raw.buffer, raw.byteOffset, raw.byteLength)
      : encoding === "hex"
        ? raw.toHex()
        : raw.toBase64(
            encoding === "base64url" ? { alphabet: "base64url", omitPadding: true } : {},
          );
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

/**
 * Reads the salt option, or draws 32 random bytes without one. A salt that is not valid in its
 * encoding is refused, never shortened to the digits that happen to parse.
 *
 * @param options - The KDF options.
 * @returns {Uint8Array} The salt's bytes.
 */
export function resolveSalt(options?: Readonly<SaltOptions>): Uint8Array {
  const salt = options?.salt;
  if (salt === undefined) return randomBytes(32);
  if (typeof salt !== "string") return salt;
  const encoding = options?.saltEncoding ?? "hex";
  const bytes = decodeSalt(salt, encoding);
  if (bytes === undefined || bytes.length === 0) {
    throw new InvalidOptionError("salt", salt, `must be whole bytes in ${encoding}`);
  }
  return bytes;
}

/**
 * Decodes a string salt, strictly: an invalid digit is an error, not a shorter salt.
 *
 * @param salt - The salt as text.
 * @param encoding - Its encoding.
 * @returns {Uint8Array | undefined} Its bytes, or undefined when it is not valid.
 */
function decodeSalt(salt: string, encoding: "hex" | "base64" | "utf8"): Uint8Array | undefined {
  if (encoding === "utf8") return new TextEncoder().encode(salt);
  try {
    return encoding === "hex" ? Uint8Array.fromHex(salt) : Uint8Array.fromBase64(salt);
  } catch {
    return undefined;
  }
}
