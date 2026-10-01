/**
 * XXH64 in plain TypeScript, after the xxHash specification by Yann Collet. Each 64-bit word is a
 * high and a low half in a `Uint32Array`, since BigInt ran it ten times slower.
 */
import { InvalidOptionError } from "../core/errors.ts";
import { FixedHash } from "../core/fixed-hash.ts";
import type { HashOptions } from "../core/types.ts";

/** Options xxHash takes besides the encoding. */
export interface XxhashOptions extends HashOptions {
  /** Unsigned 64-bit seed. Default: 0. */
  seed?: number | bigint | string;
}

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
const MASK64 = 0xffffffffffffffffn;

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
 * Computes XXH64 as the xxHash specification by Yann Collet defines it.
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

/**
 * Reads the seed option as an unsigned 64-bit integer.
 *
 * @param seed - Seed as given.
 * @returns {bigint} The seed.
 */
function seedValue(seed: number | bigint | string | undefined): bigint {
  const exact = typeof seed === "string" && /^\d+$/.test(seed);
  const value =
    (typeof seed === "number" && Number.isSafeInteger(seed)) || exact ? BigInt(seed) : seed;
  if (value === undefined) return 0n;
  if (typeof value !== "bigint" || value < 0n || value > MASK64) {
    throw new InvalidOptionError("seed", String(seed), "must be an integer from 0 to 2^64-1");
  }
  return value;
}

export class Xxhash extends FixedHash<XxhashOptions> {
  static readonly key = "xxhash";
  protected readonly about = {
    label: "xxHash (XXH64)",
    description:
      "xxHash 64-bit, an extremely fast non-cryptographic hash used in databases and compression",
    family: "xxHash",
    category: "non-cryptographic",
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
    return xxh64(bytes, seedValue(options?.seed));
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
