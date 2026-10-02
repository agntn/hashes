/**
 * Length extension. A Merkle-Damgard digest is the hash's whole state after the padding, so
 * `H(secret || message)` and the secret's length are enough to go on hashing past it and get the
 * digest of `secret || message || padding || suffix` without the secret.
 */
import { BlockHash } from "./block-hash.ts";
import { InvalidOptionError } from "./errors.ts";
import type { Hash } from "./hash.ts";
import { MerkleDamgard, assertBytes, viewOf, writeBitLength } from "./hasher.ts";
import { algorithms, create } from "./registry.ts";
import { resolveAlgorithm } from "./resolve.ts";

/** What `extendDigest` takes. */
export interface ExtendDigestOptions {
  /** A Merkle-Damgard hash whose digest is its whole state, such as `sha256` or `md5`. */
  algorithm: string;
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
 * @returns {MerkleDamgard | undefined} A fresh hasher, or nothing when its digest is not the state.
 */
function extendableHasher(algorithm: Hash): MerkleDamgard | undefined {
  if (!(algorithm instanceof BlockHash)) return undefined;
  const hasher = algorithm.hasher();
  return hasher instanceof MerkleDamgard && hasher.outputLength === hasher.stateLength
    ? hasher
    : undefined;
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
  return algorithms().filter((name) => extendableHasher(create(name)) !== undefined);
}

/**
 * Forges `H(secret || message || padding || suffix)` from `H(secret || message)` and the secret's
 * length. SHA-224, SHA-384 and SHA-512/t print part of the state, so they can't be extended.
 *
 * @param options - Algorithm, known digest, message, secret length and suffix.
 * @returns {ExtendedDigest} The message to send and its digest.
 */
export function extendDigest(options: Readonly<ExtendDigestOptions>): ExtendedDigest {
  const { digest, message, secretLength, suffix } = options;
  const algorithm = resolveAlgorithm(options.algorithm);
  const hasher = extendableHasher(algorithm);
  if (hasher === undefined) {
    throw new InvalidOptionError(
      "algorithm",
      algorithm.name(),
      `cannot be extended, use one of ${extendableAlgorithms().join(", ")}`,
    );
  }
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
  const pad = padding(hasher.blockLength, hasher.littleEndian, secretLength + message.length);
  const hashed = secretLength + message.length + pad.length;
  if (!Number.isSafeInteger(hashed + suffix.length)) {
    throw new InvalidOptionError("secretLength", secretLength, "is too long to count in bits");
  }
  const forged = new Uint8Array(message.length + pad.length + suffix.length);
  forged.set(message);
  forged.set(pad, message.length);
  forged.set(suffix, message.length + pad.length);
  return {
    algorithm: algorithm.name(),
    secretLength,
    digest: hasher.resume(digest, hashed).update(suffix).digest(),
    message: forged,
    padding: pad,
  };
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
