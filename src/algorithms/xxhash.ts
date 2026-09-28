/** XXH64 in plain TypeScript, after the xxHash specification by Yann Collet. */
import { InvalidOptionError } from "../core/errors.ts";
import { ChecksumHash } from "../core/checksum.ts";
import type { HashOptions } from "../core/types.ts";

/** Options xxHash takes besides the encoding. */
export interface XxhashOptions extends HashOptions {
  /** Unsigned 64-bit seed. Default: 0. */
  seed?: number | bigint;
}

const PRIME64_1 = 0x9e3779b185ebca87n;
const PRIME64_2 = 0xc2b2ae3d27d4eb4fn;
const PRIME64_3 = 0x165667b19e3779f9n;
const PRIME64_4 = 0x85ebca77c2b2ae63n;
const PRIME64_5 = 0x27d4eb2f165667c5n;
const MASK64 = 0xffffffffffffffffn;

/**
 * Rotates a 64-bit value left.
 *
 * @param value - Unsigned 64-bit value.
 * @param bits - Bits to rotate by, 1 to 63.
 * @returns {bigint} The rotated value.
 */
function rotl64(value: bigint, bits: bigint): bigint {
  return ((value << bits) | (value >> (64n - bits))) & MASK64;
}

/**
 * Mixes one 64-bit lane of input into an accumulator (`XXH64_round`).
 *
 * @param accumulator - Current accumulator.
 * @param lane - Eight input bytes, little-endian.
 * @returns {bigint} The new accumulator.
 */
function round(accumulator: bigint, lane: bigint): bigint {
  return (rotl64((accumulator + lane * PRIME64_2) & MASK64, 31n) * PRIME64_1) & MASK64;
}

/**
 * Folds one stripe accumulator into the hash (`XXH64_mergeRound`).
 *
 * @param hash - Current hash.
 * @param accumulator - A stripe accumulator.
 * @returns {bigint} The new hash.
 */
function mergeRound(hash: bigint, accumulator: bigint): bigint {
  return ((hash ^ round(0n, accumulator)) * PRIME64_1 + PRIME64_4) & MASK64;
}

/**
 * Hashes the 32-byte stripes and merges their four accumulators.
 *
 * @param view - The input.
 * @param seed - Unsigned 64-bit seed.
 * @param end - Offset after the last whole stripe.
 * @returns {bigint} The hash before the length and tail are mixed in.
 */
function stripes(view: DataView, seed: bigint, end: number): bigint {
  const lanes = [
    (seed + PRIME64_1 + PRIME64_2) & MASK64,
    (seed + PRIME64_2) & MASK64,
    seed,
    (seed - PRIME64_1) & MASK64,
  ];
  for (let offset = 0; offset < end; offset += 32) {
    for (let lane = 0; lane < 4; lane++) {
      lanes[lane] = round(lanes[lane]!, view.getBigUint64(offset + lane * 8, true));
    }
  }
  const [v1, v2, v3, v4] = lanes as [bigint, bigint, bigint, bigint];
  let hash = (rotl64(v1, 1n) + rotl64(v2, 7n) + rotl64(v3, 12n) + rotl64(v4, 18n)) & MASK64;
  for (const lane of lanes) hash = mergeRound(hash, lane);
  return hash;
}

/**
 * Computes XXH64 as the xxHash specification by Yann Collet defines it.
 *
 * @param data - Bytes to hash.
 * @param seed - Unsigned 64-bit seed.
 * @returns {bigint} The unsigned 64-bit hash.
 */
function xxh64(data: Uint8Array, seed: bigint): bigint {
  const view = new DataView(data.buffer, data.byteOffset, data.byteLength);
  const stripeEnd = data.length - (data.length % 32);
  let hash = data.length >= 32 ? stripes(view, seed, stripeEnd) : (seed + PRIME64_5) & MASK64;
  hash = (hash + BigInt(data.length)) & MASK64;

  let offset = stripeEnd;
  for (; offset + 8 <= data.length; offset += 8) {
    hash ^= round(0n, view.getBigUint64(offset, true));
    hash = (rotl64(hash, 27n) * PRIME64_1 + PRIME64_4) & MASK64;
  }
  if (offset + 4 <= data.length) {
    hash ^= (BigInt(view.getUint32(offset, true)) * PRIME64_1) & MASK64;
    hash = (rotl64(hash, 23n) * PRIME64_2 + PRIME64_3) & MASK64;
    offset += 4;
  }
  for (; offset < data.length; offset++) {
    hash ^= (BigInt(data[offset]!) * PRIME64_5) & MASK64;
    hash = (rotl64(hash, 11n) * PRIME64_1) & MASK64;
  }

  hash = ((hash ^ (hash >> 33n)) * PRIME64_2) & MASK64;
  hash = ((hash ^ (hash >> 29n)) * PRIME64_3) & MASK64;
  return hash ^ (hash >> 32n);
}

/**
 * Reads the seed option as an unsigned 64-bit integer.
 *
 * @param seed - Seed as given.
 * @returns {bigint} The seed.
 */
function seedValue(seed: number | bigint | undefined): bigint {
  const value = typeof seed === "number" && Number.isSafeInteger(seed) ? BigInt(seed) : seed;
  if (value === undefined) return 0n;
  if (typeof value !== "bigint" || value < 0n || value > MASK64) {
    throw new InvalidOptionError("seed", String(seed), "must be an integer from 0 to 2^64-1");
  }
  return value;
}

export class Xxhash extends ChecksumHash<XxhashOptions> {
  static readonly key = "xxhash";
  protected readonly about = {
    label: "xxHash (XXH64)",
    description:
      "xxHash 64-bit, an extremely fast non-cryptographic hash used in databases and compression",
    family: "non-cryptographic",
    digestLength: 8,
    securityNote: "NOT for security: fast hash for hash tables, bloom filters, checksums",
  } as const;
  protected override readonly options = [
    {
      name: "seed",
      type: "number",
      required: false,
      default: 0,
      description: "Seed value for xxHash",
    },
  ] as const;

  /**
   * Computes XXH64 with the seed option.
   *
   * @param bytes - Bytes to hash.
   * @param options - The seed.
   * @returns {Uint8Array} The hash, big-endian.
   */
  protected digest(bytes: Uint8Array, options?: Readonly<XxhashOptions>): Uint8Array {
    const digest = new Uint8Array(8);
    new DataView(digest.buffer).setBigUint64(0, xxh64(bytes, seedValue(options?.seed)));
    return digest;
  }

  /**
   * Reports the seed with the digest.
   *
   * @param options - The seed.
   * @returns {Record<string, unknown>} The seed used.
   */
  protected override reported(options?: Readonly<XxhashOptions>): Record<string, unknown> {
    return { seed: options?.seed ?? 0 };
  }
}
