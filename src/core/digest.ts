import { InvalidOptionError, normalizeError } from "./errors.ts";
import type {
  HashChain,
  HashInput,
  HashOption,
  HashOptions,
  HashResult,
  OutputEncoding,
} from "./types.ts";

/** The `encoding` option every algorithm takes. */
export const ENCODING_OPTION: HashOption = {
  name: "encoding",
  type: "string",
  required: false,
  default: "hex",
  description: "Output encoding: hex, base64, base64url, binary",
};

/** The `key` option of an algorithm with an HMAC mode. */
export const KEY_OPTION: HashOption = {
  name: "key",
  type: "string",
  required: false,
  description: "HMAC key; enables HMAC mode",
};

/** The `salt` option of the key derivation functions. */
export const SALT_OPTION: HashOption = {
  name: "salt",
  type: "string",
  required: false,
  random: true,
  description: "Salt in hex; 32 random bytes when omitted",
};

/** The encodings a digest comes out in. */
const OUTPUT_ENCODINGS: readonly OutputEncoding[] = ["hex", "base64", "base64url", "binary"];

/**
 * Reads the output encoding, `hex` when omitted. A typo throws instead of coming back as base64.
 *
 * @param options - The caller's options.
 * @returns {OutputEncoding} The encoding.
 */
export function outputEncoding(options?: Readonly<HashOptions>): OutputEncoding {
  const encoding: unknown = options?.encoding ?? "hex";
  const known = OUTPUT_ENCODINGS.find((name) => name === encoding);
  if (known === undefined) {
    throw new InvalidOptionError("encoding", encoding, `use one of ${OUTPUT_ENCODINGS.join(", ")}`);
  }
  return known;
}

/** The `rounds` option of a fixed-length digest. */
export const ROUNDS_OPTION: HashOption = {
  name: "rounds",
  type: "number",
  required: false,
  default: 1,
  description: "How many times to hash, each round hashing the previous digest",
};

/** The `chain` option of a fixed-length digest. */
export const CHAIN_OPTION: HashOption = {
  name: "chain",
  type: "string",
  required: false,
  default: "bytes",
  description: "What each round after the first hashes: bytes of the digest, or its lowercase hex",
};

/**
 * Reads the rounds and chain options with their defaults.
 *
 * @param options - The caller's options.
 * @returns {{ rounds: number, chain: HashChain }} How many rounds, and what each next one hashes.
 */
export function roundOptions(options?: Readonly<HashOptions>): {
  rounds: number;
  chain: HashChain;
} {
  const { rounds = 1, chain = "bytes" } = options ?? {};
  assertPositiveIntegers({ rounds });
  if (chain !== "bytes" && chain !== "hex") {
    throw new InvalidOptionError("chain", chain, "use bytes or hex");
  }
  return { rounds, chain };
}

/**
 * Refuses more than one round where rounds do not apply, instead of computing one quietly.
 *
 * @param options - The caller's options.
 * @param reason - Why one round is all there is, for the error.
 */
export function assertOneRound(options: Readonly<HashOptions> | undefined, reason: string): void {
  if (options?.rounds !== undefined && options.rounds !== 1) {
    throw new InvalidOptionError("rounds", options.rounds, reason);
  }
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
 * Tells a list of inputs from one input, since bytes are a `Uint8Array`, never an array.
 *
 * @param input - One input, or a list of them.
 * @returns {boolean} Whether it's a list.
 */
export function isInputList(
  input: HashInput | readonly HashInput[],
): input is readonly HashInput[] {
  return Array.isArray(input);
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
  // A plain Uint8Array over the same bytes, since a subclass may return a Buffer.
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

/** How a string stands for bytes: text read as UTF-8, or the bytes it spells in hex or base64. */
export type InputEncoding = "hex" | "base64" | "utf8";

/** Salt options the KDFs share. */
export interface SaltOptions {
  /** Salt as bytes or encoded text. Default: 32 random bytes. */
  salt?: HashInput;
  /** Encoding of a string salt. Default: `hex`. */
  saltEncoding?: InputEncoding;
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
  if (salt === undefined) return crypto.getRandomValues(new Uint8Array(32));
  const encoding = options?.saltEncoding ?? "hex";
  // Empty bytes are refused like an empty string: the reported salt "" could not be passed back.
  const bytes = typeof salt === "string" ? decodeText(salt, encoding) : salt;
  if (bytes === undefined || bytes.length === 0) {
    throw new InvalidOptionError("salt", salt, `must be whole bytes in ${encoding}`);
  }
  return bytes;
}

/**
 * Decodes a string, strictly: an invalid digit is an error, not fewer bytes.
 *
 * @param text - The string.
 * @param encoding - How it stands for bytes.
 * @returns {Uint8Array | undefined} Its bytes, or undefined when it is not valid.
 */
function decodeText(text: string, encoding: InputEncoding): Uint8Array | undefined {
  if (encoding === "utf8") return new TextEncoder().encode(text);
  try {
    return encoding === "hex" ? Uint8Array.fromHex(text) : Uint8Array.fromBase64(text);
  } catch {
    return undefined;
  }
}

/**
 * Reads an input given as a string. UTF-8 stays text; hex and base64 become the bytes they
 * spell, with surrounding whitespace ignored, so a public key or a raw transaction hashes as
 * bytes and not as the characters that write it down.
 *
 * @param text - The input as given.
 * @param encoding - How it stands for bytes.
 * @param name - The argument the text came from, for the error.
 * @returns {HashInput} Text, or the decoded bytes.
 */
export function decodeInput(text: string, encoding: InputEncoding, name = "input"): HashInput {
  if (encoding === "utf8") return text;
  const bytes = decodeText(text.trim(), encoding);
  if (bytes === undefined) {
    const form = encoding === "hex" ? "hex digit pairs, without a 0x prefix" : "base64";
    throw new InvalidOptionError(name, `${text.length} characters`, `must be ${form}`);
  }
  return bytes;
}

/** The largest KDF cost or key length OpenSSL took, a C int, so a larger one stays an error. */
const MAX_KDF_INTEGER = 0x7fff_ffff;

/**
 * Checks that each named value is a positive integer no larger than a C int.
 *
 * @param values - Option names with their values.
 */
export function assertPositiveIntegers(values: Readonly<Record<string, number>>): void {
  for (const [name, value] of Object.entries(values)) {
    if (!Number.isSafeInteger(value) || value < 1) {
      throw new InvalidOptionError(name, value, "must be a positive integer");
    }
    if (value > MAX_KDF_INTEGER) {
      throw new InvalidOptionError(name, value, `must be at most ${MAX_KDF_INTEGER}`);
    }
  }
}
