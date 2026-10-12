/**
 * Tiger (Anderson and Biham, FSE 1996): 64-byte blocks run through three passes of eight rounds
 * over three 64-bit words and four S-boxes of 256 words. The S-boxes come from Tiger itself, the
 * way the authors made them: every word starts as eight copies of its index byte, then the states
 * of Tiger hashing one sentence over and over swap bytes between words, through the boxes being
 * swapped. The padding starts with 0x01, and the digest is the three words, each little-endian.
 */
import { Hasher, assertBytes, viewOf, wordsToBytes, writeBitLength } from "./hasher.ts";

/** Bytes per block. */
const BLOCK = 64;
/** Where the bit length starts in the last block. */
const LENGTH_FIELD = BLOCK - 8;
/** The 64 bytes the authors hash to shuffle the S-boxes. */
const SEED = "Tiger - A Fast New Hash Function, by Ross Anderson and Eli Biham";
/** Times the shuffle walks through all 1024 S-box words. */
const SEED_PASSES = 5;

/** The starting words a, b and c, each as its low then its high half. */
const IV = /* @__PURE__ */ new Int32Array([
  0x89abcdef, 0x01234567, 0x76543210, 0xfedcba98, 0xc3b2e187, 0xf096a5b4,
]);

/** Where a, b and c sit in `W`. */
const A = 0;
const B = 2;
const C = 4;
/** Where the eight key words start in `W`. */
const X = 6;

/** Registers a, b, c, then the block's eight key words, low half first. Hashing is synchronous. */
const W = /* @__PURE__ */ new Int32Array(22);

/** The four S-boxes as 1024 words, low half first. Empty until the first hasher builds them. */
const T = /* @__PURE__ */ new Int32Array(2048);
/** Whether `T` holds the S-boxes yet. */
let built = false;

/**
 * Adds a 64-bit word to the one at `i` in `W`.
 *
 * @param i - Index of its low half.
 * @param low - Low half of the word to add.
 * @param high - High half of it.
 */
function add(i: number, low: number, high: number): void {
  const sum = (W[i]! >>> 0) + (low >>> 0);
  W[i + 1] = (W[i + 1]! + high + (sum > 0xffff_ffff ? 1 : 0)) | 0;
  W[i] = sum | 0;
}

/**
 * Subtracts a 64-bit word from the one at `i` in `W`.
 *
 * @param i - Index of its low half.
 * @param low - Low half of the word to subtract.
 * @param high - High half of it.
 */
function sub(i: number, low: number, high: number): void {
  const difference = (W[i]! >>> 0) - (low >>> 0);
  W[i + 1] = (W[i + 1]! - high - (difference < 0 ? 1 : 0)) | 0;
  W[i] = difference | 0;
}

/**
 * Multiplies the 64-bit word at `i` in `W` by 5, 7 or 9. The low product stays under 2^36, so a
 * double holds it exactly.
 *
 * @param i - Index of its low half.
 * @param factor - The pass's multiplier.
 */
function mul(i: number, factor: number): void {
  const product = (W[i]! >>> 0) * factor;
  W[i + 1] = (Math.imul(W[i + 1]!, factor) + Math.floor(product / 0x1_0000_0000)) | 0;
  W[i] = product | 0;
}

/**
 * Where an S-box word sits: box `box`, picked by the byte of `half` that starts at bit `shift`.
 *
 * @param box - The S-box, 0 to 3 for t1 to t4.
 * @param half - A half of register c.
 * @param shift - The byte's lowest bit in that half.
 * @returns {number} Index of the word's low half.
 */
function slot(box: number, half: number, shift: number): number {
  return (box << 9) | (((half >>> shift) & 0xff) << 1);
}

/**
 * One round: c takes a key word, then its even bytes pick the S-box words a loses and its odd
 * bytes the ones b gains, before b is multiplied.
 *
 * @param a - Where a sits in `W`, in this round's role.
 * @param b - Where b sits.
 * @param c - Where c sits.
 * @param x - Where the key word sits.
 * @param factor - The pass's multiplier.
 */
function round(a: number, b: number, c: number, x: number, factor: number): void {
  const low = W[c]! ^ W[x]!;
  const high = W[c + 1]! ^ W[x + 1]!;
  W[c] = low;
  W[c + 1] = high;
  const e0 = slot(0, low, 0);
  const e2 = slot(1, low, 16);
  const e4 = slot(2, high, 0);
  const e6 = slot(3, high, 16);
  sub(a, T[e0]! ^ T[e2]! ^ T[e4]! ^ T[e6]!, T[e0 + 1]! ^ T[e2 + 1]! ^ T[e4 + 1]! ^ T[e6 + 1]!);
  const e1 = slot(3, low, 8);
  const e3 = slot(2, low, 24);
  const e5 = slot(1, high, 8);
  const e7 = slot(0, high, 24);
  add(b, T[e1]! ^ T[e3]! ^ T[e5]! ^ T[e7]!, T[e1 + 1]! ^ T[e3 + 1]! ^ T[e5 + 1]! ^ T[e7 + 1]!);
  mul(b, factor);
}

/**
 * Eight rounds, one per key word, the registers trading roles after each.
 *
 * @param a - Where the pass's a sits in `W`.
 * @param b - Where its b sits.
 * @param c - Where its c sits.
 * @param factor - 5, 7, then 9.
 */
function pass(a: number, b: number, c: number, factor: number): void {
  round(a, b, c, X, factor);
  round(b, c, a, X + 2, factor);
  round(c, a, b, X + 4, factor);
  round(a, b, c, X + 6, factor);
  round(b, c, a, X + 8, factor);
  round(c, a, b, X + 10, factor);
  round(a, b, c, X + 12, factor);
  round(b, c, a, X + 14, factor);
}

/**
 * Subtracts `W[from] ^ (~W[not] << 19)` from the word at `i`.
 *
 * @param i - The word that loses it.
 * @param from - The word mixed in.
 * @param not - The word inverted and shifted left.
 */
function subLeft(i: number, from: number, not: number): void {
  const low = ~W[not]!;
  const high = ~W[not + 1]!;
  sub(i, W[from]! ^ (low << 19), W[from + 1]! ^ ((high << 19) | (low >>> 13)));
}

/**
 * Subtracts `W[from] ^ (~W[not] >>> 23)` from the word at `i`.
 *
 * @param i - The word that loses it.
 * @param from - The word mixed in.
 * @param not - The word inverted and shifted right.
 */
function subRight(i: number, from: number, not: number): void {
  const low = ~W[not]!;
  const high = ~W[not + 1]!;
  sub(i, W[from]! ^ ((low >>> 23) | (high << 9)), W[from + 1]! ^ (high >>> 23));
}

/**
 * XORs the word at `from` into the one at `i`.
 *
 * @param i - The word that changes.
 * @param from - The word it takes.
 */
function xorWord(i: number, from: number): void {
  W[i] = W[i]! ^ W[from]!;
  W[i + 1] = W[i + 1]! ^ W[from + 1]!;
}

/**
 * Adds the word at `from` to the one at `i`.
 *
 * @param i - The word that changes.
 * @param from - The word it takes.
 */
function addWord(i: number, from: number): void {
  add(i, W[from]!, W[from + 1]!);
}

/** Stirs the eight key words between passes. */
function schedule(): void {
  const [x0, x1, x2, x3, x4, x5, x6, x7] = [X, X + 2, X + 4, X + 6, X + 8, X + 10, X + 12, X + 14];
  sub(x0, W[x7]! ^ 0xa5a5a5a5, W[x7 + 1]! ^ 0xa5a5a5a5);
  xorWord(x1, x0);
  addWord(x2, x1);
  subLeft(x3, x2, x1);
  xorWord(x4, x3);
  addWord(x5, x4);
  subRight(x6, x5, x4);
  xorWord(x7, x6);
  addWord(x0, x7);
  subLeft(x1, x0, x7);
  xorWord(x2, x1);
  addWord(x3, x2);
  subRight(x4, x3, x2);
  xorWord(x5, x4);
  addWord(x6, x5);
  sub(x7, W[x6]! ^ 0x89abcdef, W[x6 + 1]! ^ 0x01234567);
}

/**
 * Runs one block through the three passes and feeds the result forward into the state.
 *
 * @param state - a, b and c, low half first.
 * @param block - Bytes holding the block.
 * @param offset - Where the block starts.
 */
function compress(state: Int32Array, block: Uint8Array, offset: number): void {
  for (let i = 0; i < 16; i++) {
    const at = offset + 4 * i;
    W[X + i] = block[at]! | (block[at + 1]! << 8) | (block[at + 2]! << 16) | (block[at + 3]! << 24);
  }
  W.set(state);
  pass(A, B, C, 5);
  schedule();
  pass(C, A, B, 7);
  schedule();
  pass(B, C, A, 9);
  W[A] = W[A]! ^ state[0]!;
  W[A + 1] = W[A + 1]! ^ state[1]!;
  sub(B, state[2]!, state[3]!);
  add(C, state[4]!, state[5]!);
  state.set(W.subarray(0, 6));
}

/**
 * Swaps each byte of one S-box word with the same byte of the word that byte of a register picks
 * in the same box.
 *
 * @param state - The three registers of the Tiger run that shuffles.
 * @param register - Which of them picks, 0 to 2.
 * @param word - The word's index among all 1024.
 */
function swapBytes(state: Int32Array, register: number, word: number): void {
  const box = word & ~0xff;
  for (let byte = 0; byte < 8; byte++) {
    const half = byte >> 2;
    const shift = (byte & 3) << 3;
    const mask = 0xff << shift;
    const picked = (state[2 * register + half]! >>> shift) & 0xff;
    const i = (word << 1) + half;
    const j = ((box | picked) << 1) + half;
    const kept = T[i]! & mask;
    T[i] = (T[i]! & ~mask) | (T[j]! & mask);
    T[j] = (T[j]! & ~mask) | kept;
  }
}

/** Builds the S-boxes like the authors did, Tiger hashing through the boxes it shuffles. */
function build(): void {
  for (let i = 0; i < T.length; i++) T[i] = Math.imul((i >> 1) & 0xff, 0x0101_0101);
  const state = IV.slice();
  const seed = new TextEncoder().encode(SEED);
  for (let step = 0; step < SEED_PASSES * 1024; step++) {
    const register = step % 3;
    if (register === 0) compress(state, seed, 0);
    swapBytes(state, register, ((step & 3) << 8) | ((step >> 2) & 0xff));
  }
  built = true;
}

/** Tiger, the original: 192 bits, three passes, 0x01 padding and little-endian words. */
export class TigerHasher extends Hasher {
  readonly blockLength = BLOCK;
  readonly outputLength = 24;
  /** a, b and c, low half first. */
  private readonly state = IV.slice();
  /** The partial block not compressed yet. */
  private readonly buffer = new Uint8Array(BLOCK);
  /** Bytes waiting in the buffer. */
  private position = 0;
  /** Bytes absorbed so far. */
  private length = 0;

  constructor() {
    super();
    if (!built) build();
  }

  update(data: Uint8Array): this {
    assertBytes(data, "data");
    const { buffer, state } = this;
    const length = data.length;
    let position = this.position;
    let offset = 0;
    this.length += length;
    if (position > 0) {
      while (offset < length && position < BLOCK) buffer[position++] = data[offset++]!;
      if (position < BLOCK) {
        this.position = position;
        return this;
      }
      compress(state, buffer, 0);
      position = 0;
    }
    for (; length - offset >= BLOCK; offset += BLOCK) compress(state, data, offset);
    while (offset < length) buffer[position++] = data[offset++]!;
    this.position = position;
    return this;
  }

  digestInto(out: Uint8Array): void {
    const { buffer, state } = this;
    let position = this.position;
    buffer[position++] = 0x01;
    if (position > LENGTH_FIELD) {
      buffer.fill(0, position);
      compress(state, buffer, 0);
      position = 0;
    }
    buffer.fill(0, position, LENGTH_FIELD);
    writeBitLength(viewOf(buffer), BLOCK, this.length, true);
    compress(state, buffer, 0);
    wordsToBytes(state, out, this.outputLength, true);
  }

  load(source: this): this {
    this.state.set(source.state);
    this.buffer.set(source.buffer);
    this.position = source.position;
    this.length = source.length;
    return this;
  }
}
