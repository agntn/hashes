/**
 * xxHash in plain TypeScript, after the specification by Yann Collet: XXH64, and XXH32 with
 * `bits: 32`. XXH64 keeps each 64-bit word as a high and a low half in a `Uint32Array`, since
 * BigInt ran it ten times slower. lz4 frames check their blocks and content with XXH32, zstd
 * frames with XXH64.
 */
import { InvalidOptionError } from "./errors.ts";
import { assertBytes } from "./hasher.ts";

const PRIME32_1 = 0x9e3779b1;
const PRIME32_2 = 0x85ebca77;
const PRIME32_3 = 0xc2b2ae3d;
const PRIME32_4 = 0x27d4eb2f;
const PRIME32_5 = 0x165667b1;

/**
 * Rotates a 32-bit word left.
 *
 * @param value - The word.
 * @param bits - Bits to rotate by, 1 to 31.
 * @returns {number} The rotated word, signed.
 */
function rotl32(value: number, bits: number): number {
  return (value << bits) | (value >>> (32 - bits));
}

/**
 * Mixes one input word into a lane (`XXH32_round`).
 *
 * @param lane - The accumulator.
 * @param word - Four input bytes, little-endian.
 * @returns {number} The new accumulator.
 */
function round32(lane: number, word: number): number {
  return Math.imul(rotl32((lane + Math.imul(word, PRIME32_2)) | 0, 13), PRIME32_1);
}

/**
 * Computes XXH32.
 *
 * @param data - Bytes to hash.
 * @param seed - Unsigned 32-bit seed.
 * @returns {Uint8Array} The hash, big-endian, as `xxh32sum` prints it.
 */
function xxh32(data: Uint8Array, seed: number): Uint8Array {
  const view = new DataView(data.buffer, data.byteOffset, data.byteLength);
  const length = data.length;
  let offset = 0;
  let hash: number;
  if (length >= 16) {
    let v1 = (seed + PRIME32_1 + PRIME32_2) | 0;
    let v2 = (seed + PRIME32_2) | 0;
    let v3 = seed | 0;
    let v4 = (seed - PRIME32_1) | 0;
    const end = length - 16;
    for (; offset <= end; offset += 16) {
      v1 = round32(v1, view.getUint32(offset, true));
      v2 = round32(v2, view.getUint32(offset + 4, true));
      v3 = round32(v3, view.getUint32(offset + 8, true));
      v4 = round32(v4, view.getUint32(offset + 12, true));
    }
    hash = (rotl32(v1, 1) + rotl32(v2, 7) + rotl32(v3, 12) + rotl32(v4, 18)) | 0;
  } else {
    hash = (seed + PRIME32_5) | 0;
  }
  hash = (hash + length) | 0;
  for (; offset + 4 <= length; offset += 4) {
    hash = (hash + Math.imul(view.getUint32(offset, true), PRIME32_3)) | 0;
    hash = Math.imul(rotl32(hash, 17), PRIME32_4);
  }
  for (; offset < length; offset++) {
    hash = (hash + Math.imul(data[offset]!, PRIME32_5)) | 0;
    hash = Math.imul(rotl32(hash, 11), PRIME32_1);
  }
  hash ^= hash >>> 15;
  hash = Math.imul(hash, PRIME32_2);
  hash ^= hash >>> 13;
  hash = Math.imul(hash, PRIME32_3);
  hash ^= hash >>> 16;
  const digest = new Uint8Array(4);
  new DataView(digest.buffer).setInt32(0, hash);
  return digest;
}

const MASK64 = 0xffffffffffffffffn;
const PRIME64_1_HIGH = 0x9e3779b1;
const PRIME64_1_LOW = 0x85ebca87;
const PRIME64_2_HIGH = 0xc2b2ae3d;
const PRIME64_2_LOW = 0x27d4eb4f;
const PRIME64_3_HIGH = 0x165667b1;
const PRIME64_3_LOW = 0x9e3779f9;
const PRIME64_4_HIGH = 0x85ebca77;
const PRIME64_4_LOW = 0xc2b2ae63;
const PRIME64_5_HIGH = 0x27d4eb2f;
const PRIME64_5_LOW = 0x165667c5;
/** 2^64 - PRIME64_1, so adding it subtracts PRIME64_1. */
const MINUS_PRIME64_1_HIGH = 0x61c8864e;
const MINUS_PRIME64_1_LOW = 0x7a143579;

/** Where the state keeps the four stripe accumulators, the hash and a scratch word. */
const HASH = 8;
const SCRATCH = 10;

/**
 * The top 32 bits of a 64-bit product, from 16-bit pieces that stay exact in a double.
 *
 * @param a - Unsigned 32-bit value.
 * @param b - Unsigned 32-bit value.
 * @returns {number} The top 32 bits of `a * b`.
 */
function multiplyHigh(a: number, b: number): number {
  const a0 = a & 0xffff;
  const a1 = a >>> 16;
  const b0 = b & 0xffff;
  const b1 = b >>> 16;
  const low = a0 * b1;
  const high = a1 * b0;
  const carry = ((a0 * b0) >>> 16) + (low & 0xffff) + (high & 0xffff);
  return a1 * b1 + (low >>> 16) + (high >>> 16) + (carry >>> 16);
}

/**
 * Multiplies the word at `i` by a prime; the `Uint32Array` store drops what overflows 2^64.
 *
 * @param s - The state.
 * @param i - Index of the word's high half.
 * @param high - The prime's high half.
 * @param low - The prime's low half.
 */
function multiply(s: Uint32Array, i: number, high: number, low: number): void {
  const h = s[i]!;
  const l = s[i + 1]!;
  s[i] = multiplyHigh(l, low) + Math.imul(h, low) + Math.imul(l, high);
  s[i + 1] = Math.imul(l, low);
}

/**
 * Adds an unsigned 64-bit value to the word at `i`, modulo 2^64.
 *
 * @param s - The state.
 * @param i - Index of the word's high half.
 * @param high - High half of the value.
 * @param low - Low half of the value.
 */
function add(s: Uint32Array, i: number, high: number, low: number): void {
  const sum = s[i + 1]! + low;
  s[i] = s[i]! + high + (sum > 0xffffffff ? 1 : 0);
  s[i + 1] = sum;
}

/**
 * XORs a 64-bit value into the word at `i`.
 *
 * @param s - The state.
 * @param i - Index of the word's high half.
 * @param high - High half of the value.
 * @param low - Low half of the value.
 */
function xor(s: Uint32Array, i: number, high: number, low: number): void {
  s[i] = s[i]! ^ high;
  s[i + 1] = s[i + 1]! ^ low;
}

/**
 * Rotates the word at `i` left.
 *
 * @param s - The state.
 * @param i - Index of the word's high half.
 * @param bits - Bits to rotate by, 1 to 31.
 */
function rotate(s: Uint32Array, i: number, bits: number): void {
  const h = s[i]!;
  const l = s[i + 1]!;
  s[i] = (h << bits) | (l >>> (32 - bits));
  s[i + 1] = (l << bits) | (h >>> (32 - bits));
}

/**
 * Mixes the scratch word into the accumulator at `i` (`XXH64_round`), and spends the scratch.
 *
 * @param s - The state.
 * @param i - Index of the accumulator's high half.
 */
function round(s: Uint32Array, i: number): void {
  multiply(s, SCRATCH, PRIME64_2_HIGH, PRIME64_2_LOW);
  add(s, i, s[SCRATCH]!, s[SCRATCH + 1]!);
  rotate(s, i, 31);
  multiply(s, i, PRIME64_1_HIGH, PRIME64_1_LOW);
}

/**
 * Runs `XXH64_round` on the scratch word from a zero accumulator and XORs it into the hash.
 *
 * @param s - The state.
 */
function mixScratch(s: Uint32Array): void {
  multiply(s, SCRATCH, PRIME64_2_HIGH, PRIME64_2_LOW);
  rotate(s, SCRATCH, 31);
  multiply(s, SCRATCH, PRIME64_1_HIGH, PRIME64_1_LOW);
  xor(s, HASH, s[SCRATCH]!, s[SCRATCH + 1]!);
}

/**
 * Hashes the 32-byte stripes and merges their four accumulators into the hash.
 *
 * @param s - The state, with the seed in every accumulator.
 * @param view - The input.
 * @param end - Offset after the last whole stripe.
 */
function stripes(s: Uint32Array, view: DataView, end: number): void {
  add(s, 0, PRIME64_1_HIGH, PRIME64_1_LOW);
  add(s, 0, PRIME64_2_HIGH, PRIME64_2_LOW);
  add(s, 2, PRIME64_2_HIGH, PRIME64_2_LOW);
  add(s, 6, MINUS_PRIME64_1_HIGH, MINUS_PRIME64_1_LOW);
  for (let offset = 0; offset < end; offset += 32) {
    for (let lane = 0; lane < 8; lane += 2) {
      s[SCRATCH] = view.getUint32(offset + lane * 4 + 4, true);
      s[SCRATCH + 1] = view.getUint32(offset + lane * 4, true);
      round(s, lane);
    }
  }
  s[HASH] = 0;
  s[HASH + 1] = 0;
  for (const [lane, bits] of [
    [0, 1],
    [2, 7],
    [4, 12],
    [6, 18],
  ] as const) {
    s[SCRATCH] = s[lane]!;
    s[SCRATCH + 1] = s[lane + 1]!;
    rotate(s, SCRATCH, bits);
    add(s, HASH, s[SCRATCH]!, s[SCRATCH + 1]!);
  }
  for (let lane = 0; lane < 8; lane += 2) {
    s[SCRATCH] = s[lane]!;
    s[SCRATCH + 1] = s[lane + 1]!;
    mixScratch(s);
    multiply(s, HASH, PRIME64_1_HIGH, PRIME64_1_LOW);
    add(s, HASH, PRIME64_4_HIGH, PRIME64_4_LOW);
  }
}

/**
 * Computes XXH64.
 *
 * @param data - Bytes to hash.
 * @param seed - Unsigned 64-bit seed.
 * @returns {Uint8Array} The hash, big-endian.
 */
function xxh64(data: Uint8Array, seed: bigint): Uint8Array {
  const view = new DataView(data.buffer, data.byteOffset, data.byteLength);
  const seedHigh = Number(seed >> 32n);
  const seedLow = Number(seed & 0xffffffffn);
  const s = new Uint32Array(12);
  const stripeEnd = data.length - (data.length % 32);
  if (data.length >= 32) {
    for (let lane = 0; lane < 8; lane += 2) {
      s[lane] = seedHigh;
      s[lane + 1] = seedLow;
    }
    stripes(s, view, stripeEnd);
  } else {
    s[HASH] = seedHigh;
    s[HASH + 1] = seedLow;
    add(s, HASH, PRIME64_5_HIGH, PRIME64_5_LOW);
  }
  add(s, HASH, Math.floor(data.length / 0x1_0000_0000), data.length >>> 0);

  let offset = stripeEnd;
  for (; offset + 8 <= data.length; offset += 8) {
    s[SCRATCH] = view.getUint32(offset + 4, true);
    s[SCRATCH + 1] = view.getUint32(offset, true);
    mixScratch(s);
    rotate(s, HASH, 27);
    multiply(s, HASH, PRIME64_1_HIGH, PRIME64_1_LOW);
    add(s, HASH, PRIME64_4_HIGH, PRIME64_4_LOW);
  }
  if (offset + 4 <= data.length) {
    s[SCRATCH] = 0;
    s[SCRATCH + 1] = view.getUint32(offset, true);
    multiply(s, SCRATCH, PRIME64_1_HIGH, PRIME64_1_LOW);
    xor(s, HASH, s[SCRATCH]!, s[SCRATCH + 1]!);
    rotate(s, HASH, 23);
    multiply(s, HASH, PRIME64_2_HIGH, PRIME64_2_LOW);
    add(s, HASH, PRIME64_3_HIGH, PRIME64_3_LOW);
    offset += 4;
  }
  for (; offset < data.length; offset++) {
    s[SCRATCH] = 0;
    s[SCRATCH + 1] = data[offset]!;
    multiply(s, SCRATCH, PRIME64_5_HIGH, PRIME64_5_LOW);
    xor(s, HASH, s[SCRATCH]!, s[SCRATCH + 1]!);
    rotate(s, HASH, 11);
    multiply(s, HASH, PRIME64_1_HIGH, PRIME64_1_LOW);
  }

  xor(s, HASH, 0, s[HASH]! >>> 1);
  multiply(s, HASH, PRIME64_2_HIGH, PRIME64_2_LOW);
  xor(s, HASH, s[HASH]! >>> 29, (s[HASH + 1]! >>> 29) | (s[HASH]! << 3));
  multiply(s, HASH, PRIME64_3_HIGH, PRIME64_3_LOW);
  xor(s, HASH, 0, s[HASH]!);

  const digest = new Uint8Array(8);
  const out = new DataView(digest.buffer);
  out.setUint32(0, s[HASH]!);
  out.setUint32(4, s[HASH + 1]!);
  return digest;
}

/** The xxHash widths: XXH32 and XXH64. */
export const XXHASH_BITS = [32, 64] as const;

/** An xxHash width. */
export type XxhashBits = (typeof XXHASH_BITS)[number];

/**
 * Reads a seed as an unsigned integer of `bits` bits.
 *
 * @param seed - The seed as passed.
 * @param bits - 32 or 64.
 * @returns {bigint} The seed.
 */
function seedOf(seed: unknown, bits: XxhashBits): bigint {
  const value = typeof seed === "number" && Number.isSafeInteger(seed) ? BigInt(seed) : seed;
  if (typeof value !== "bigint" || value < 0n || value > (bits === 32 ? 0xffffffffn : MASK64)) {
    throw new InvalidOptionError("seed", String(seed), `must be an integer from 0 to 2^${bits}-1`);
  }
  return value;
}

/**
 * Computes xxHash: XXH64 by default, XXH32 with `bits` 32.
 *
 * @param data - Bytes to hash.
 * @param bits - 64 for XXH64, 32 for XXH32. Default: 64.
 * @param seed - Unsigned seed of that many bits, as a number or a bigint. Default: 0.
 * @returns {Uint8Array} The hash, big-endian, as `xxhsum` prints it.
 */
export function xxhash(
  data: Uint8Array,
  bits: XxhashBits = 64,
  seed: number | bigint = 0,
): Uint8Array {
  assertBytes(data, "data");
  if (bits !== 32 && bits !== 64) {
    throw new InvalidOptionError("bits", bits, `use one of ${XXHASH_BITS.join(", ")}`);
  }
  const value = seedOf(seed, bits);
  return bits === 32 ? xxh32(data, Number(value)) : xxh64(data, value);
}
