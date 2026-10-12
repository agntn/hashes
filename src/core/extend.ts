/**
 * Length extension. A Merkle-Damgard digest is the hash's whole state after the padding, so
 * `H(secret || message)` and the secret's length are enough to go on hashing past it and get the
 * digest of `secret || message || padding || suffix` without the secret.
 */
import { BlockHash } from "./block-hash.ts";
import { assertOneRound } from "./digest.ts";
import { InvalidOptionError } from "./errors.ts";
import { ROUND_OPTIONS } from "./fixed-hash.ts";
import type { Hash } from "./hash.ts";
import { MerkleDamgard, assertBytes, viewOf, writeBitLength } from "./hasher.ts";
import { type ParameterValue, checkedParameters, parameterOptions } from "./options.ts";
import { algorithms, create } from "./registry.ts";
import { resolveAlgorithm } from "./resolve.ts";
import { ResumableHasher } from "./resumable.ts";
import type { HashOptions } from "./types.ts";

/** Option values by name, as `parameters` carries them. */
type OptionValues = Readonly<Record<string, ParameterValue>>;

/** What `extendDigest` takes. */
export interface ExtendDigestOptions {
  /** A Merkle-Damgard hash whose digest is its whole state, such as `sha256` or `md5`. */
  algorithm: string;
  /** The algorithm's own options, such as HAVAL's `passes` and its `bits`, which must be 256. */
  parameters?: OptionValues;
  /** The known digest of the secret followed by the message. */
  digest: Uint8Array;
  /** The message that followed the secret. */
  message: Uint8Array;
  /** Bytes of the secret, which itself stays unknown. */
  secretLength: number;
  /** What to append. */
  suffix: Uint8Array;
}

/** A forged message and its digest. */
export interface ExtendedDigest {
  /** The algorithm's registry name. */
  algorithm: string;
  /** The options the digest was read with, defaults included, such as HAVAL's passes and bits. */
  parameters: Record<string, ParameterValue>;
  /** The secret length this answer assumes. */
  secretLength: number;
  /** The digest of the secret followed by `message`. */
  digest: Uint8Array;
  /** The message to send: the original, the padding, then the suffix. */
  message: Uint8Array;
  /** The padding the hash put after the secret and the original message. */
  padding: Uint8Array;
}

/**
 * The hasher of an algorithm that length extension works on.
 *
 * @param algorithm - The algorithm.
 * @param parameters - Its own options.
 * @returns {MerkleDamgard | ResumableHasher | undefined} A fresh hasher, or nothing.
 */
function extendableHasher(
  algorithm: Hash,
  parameters: OptionValues,
): MerkleDamgard | ResumableHasher | undefined {
  if (!(algorithm instanceof BlockHash)) return undefined;
  const hasher = algorithm.hasher(parameters as HashOptions);
  if (!(hasher instanceof MerkleDamgard || hasher instanceof ResumableHasher)) return undefined;
  return hasher.outputLength === hasher.stateLength ? hasher : undefined;
}

/**
 * The one option value that makes the digest the whole state, such as HAVAL's `bits: 256`.
 *
 * @param algorithm - The algorithm.
 * @param parameters - Its own options as given.
 * @returns {[string, ParameterValue] | undefined} The option and its value, or nothing.
 */
function extendingChoice(
  algorithm: Hash,
  parameters: OptionValues,
): [string, ParameterValue] | undefined {
  for (const option of parameterOptions(algorithm)) {
    if (ROUND_OPTIONS.some((round) => round.name === option.name)) continue;
    const current = parameters[option.name] ?? option.default;
    const fits = (option.choices ?? []).find(
      (choice) =>
        choice !== current &&
        extendableHasher(algorithm, { ...parameters, [option.name]: choice }) !== undefined,
    );
    if (fits !== undefined) return [option.name, fits];
  }
  return undefined;
}

/**
 * Why a call can't be extended, with the option that fixes it when there is one.
 *
 * @param algorithm - The algorithm.
 * @param parameters - Its own options as given.
 * @returns {InvalidOptionError} The error to throw.
 */
function refusal(algorithm: Hash, parameters: OptionValues): InvalidOptionError {
  const choice = extendingChoice(algorithm, parameters);
  if (choice === undefined) {
    return new InvalidOptionError(
      "algorithm",
      algorithm.name(),
      `cannot be extended, use one of ${extendableAlgorithms().join(", ")}`,
    );
  }
  const [name, value] = choice;
  const declared = parameterOptions(algorithm).find((option) => option.name === name);
  return new InvalidOptionError(
    name,
    parameters[name] ?? declared?.default,
    `${algorithm.name()} extends with ${name} ${String(value)}, where the digest is the whole state`,
  );
}

/**
 * The padding a Merkle-Damgard hash appends after `length` bytes: 0x80, zeros, then the bit length.
 *
 * @param block - The hash's block length.
 * @param littleEndian - Byte order of the bit length.
 * @param length - Bytes hashed before the padding.
 * @returns {Uint8Array} The padding, ending on a block boundary.
 */
function padding(block: number, littleEndian: boolean, length: number): Uint8Array {
  const least = 1 + (block >> 3);
  const size = least + ((block - ((length + least) % block)) % block);
  const out = new Uint8Array(size);
  out[0] = 0x80;
  writeBitLength(viewOf(out), size, length, littleEndian);
  return out;
}

/**
 * Lists the registered algorithms whose digests can be extended.
 *
 * @returns {string[]} Their names, in listing order.
 */
export function extendableAlgorithms(): string[] {
  return algorithms().filter((name) => {
    const algorithm = create(name);
    return (
      extendableHasher(algorithm, {}) !== undefined || extendingChoice(algorithm, {}) !== undefined
    );
  });
}

/**
 * Forges `H(secret || message || padding || suffix)` from `H(secret || message)` and the secret's
 * length. SHA-224, SHA-384, SHA-512/t and HAVAL below 256 bits print part of the state, so they
 * can't be extended.
 *
 * @param options - Algorithm and its options, known digest, message, secret length and suffix.
 * @returns {ExtendedDigest} The message to send and its digest.
 */
export function extendDigest(options: Readonly<ExtendDigestOptions>): ExtendedDigest {
  const { digest, message, secretLength, suffix } = options;
  const algorithm = resolveAlgorithm(options.algorithm);
  const parameters = checkedParameters(algorithm, options.parameters ?? {});
  assertOneRound(parameters, "a second round hides the state, so it can't be extended");
  const hasher = extendableHasher(algorithm, parameters);
  if (hasher === undefined) throw refusal(algorithm, parameters);
  assertBytes(digest, "digest");
  assertBytes(message, "message");
  assertBytes(suffix, "suffix");
  if (!Number.isSafeInteger(secretLength) || secretLength < 0) {
    throw new InvalidOptionError("secretLength", secretLength, "must be a whole number from 0");
  }
  if (digest.length !== hasher.outputLength) {
    throw new InvalidOptionError(
      "digest",
      `${digest.length} bytes`,
      `${algorithm.name()} digests are ${hasher.outputLength} bytes`,
    );
  }
  const known = secretLength + message.length;
  const pad =
    hasher instanceof ResumableHasher
      ? hasher.padding(known)
      : padding(hasher.blockLength, hasher.littleEndian, known);
  const hashed = known + pad.length;
  if (!Number.isSafeInteger(hashed + suffix.length)) {
    throw new InvalidOptionError("secretLength", secretLength, "is too long to count in bits");
  }
  const forged = new Uint8Array(message.length + pad.length + suffix.length);
  forged.set(message);
  forged.set(pad, message.length);
  forged.set(suffix, message.length + pad.length);
  return {
    algorithm: algorithm.name(),
    parameters: reportedParameters(algorithm, parameters),
    secretLength,
    digest: hasher.resume(digest, hashed).update(suffix).digest(),
    message: forged,
    padding: pad,
  };
}

/**
 * The options `hash()` reports, HAVAL's passes and bits among them, read off a hash of nothing.
 *
 * @param algorithm - The algorithm.
 * @param parameters - Its own options as given.
 * @returns {Record<string, ParameterValue>} The options without the encoding.
 */
function reportedParameters(
  algorithm: Hash,
  parameters: OptionValues,
): Record<string, ParameterValue> {
  const result = algorithm.hash(new Uint8Array(0), { ...parameters, encoding: "binary" });
  const { encoding: _encoding, ...reported } = result.options;
  return reported as Record<string, ParameterValue>;
}

/**
 * Lists the secret lengths from `first` to `last`, the range the tools and the CLI try.
 *
 * @param first - The shortest secret.
 * @param last - The longest secret, `first` when omitted.
 * @param most - How many lengths one call may try.
 * @returns {number[]} The lengths, shortest first.
 */
export function secretLengths(first: number, last: number | undefined, most: number): number[] {
  const end = last ?? first;
  if (!Number.isSafeInteger(first) || first < 0) {
    throw new InvalidOptionError("secretLength", first, "must be a whole number from 0");
  }
  if (!Number.isSafeInteger(end) || end < first) {
    throw new InvalidOptionError("secretLengthMax", end, `must be a whole number from ${first}`);
  }
  if (end - first >= most) {
    throw new InvalidOptionError(
      "secretLengthMax",
      end,
      `tries ${end - first + 1} lengths, at most ${most} in one call`,
    );
  }
  return Array.from({ length: end - first + 1 }, (_, index) => first + index);
}
