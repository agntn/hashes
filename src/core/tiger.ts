/**
 * Tiger (Anderson and Biham, FSE 1996): 64-byte blocks run through three passes of eight rounds
 * over three 64-bit words and four S-boxes of 256 words. The S-boxes come from Tiger itself, the
 * way the authors made them: every word starts as eight copies of its index byte, then the states
 * of Tiger hashing one sentence over and over swap bytes between words, through the boxes being
 * swapped. The padding starts with 0x01, and the digest is the three words, each little-endian.
 */
import { HashError } from "./errors.ts";
import { assertBytes, viewOf, wordsToBytes } from "./hasher.ts";
import { ResumableHasher } from "./resumable.ts";

/** Bytes per block. */
const BLOCK = 64;
/** Where the bit length starts in the last block. */
const LENGTH_FIELD = BLOCK - 8;
/** The byte the padding opens with. Tiger2 is the same hash with 0x80 here. */
const MARKER = 0x01;
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
const [X0, X1, X2, X3, X4, X5, X6, X7] = [X, X + 2, X + 4, X + 6, X + 8, X + 10, X + 12, X + 14];

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
  round(a, b, c, X0, factor);
  round(b, c, a, X1, factor);
  round(c, a, b, X2, factor);
  round(a, b, c, X3, factor);
  round(b, c, a, X4, factor);
  round(c, a, b, X5, factor);
  round(a, b, c, X6, factor);
  round(b, c, a, X7, factor);
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
  sub(X0, W[X7]! ^ 0xa5a5a5a5, W[X7 + 1]! ^ 0xa5a5a5a5);
  xorWord(X1, X0);
  addWord(X2, X1);
  subLeft(X3, X2, X1);
  xorWord(X4, X3);
  addWord(X5, X4);
  subRight(X6, X5, X4);
  xorWord(X7, X6);
  addWord(X0, X7);
  subLeft(X1, X0, X7);
  xorWord(X2, X1);
  addWord(X3, X2);
  subRight(X4, X3, X2);
  xorWord(X5, X4);
  addWord(X6, X5);
  sub(X7, W[X6]! ^ 0x89abcdef, W[X6 + 1]! ^ 0x01234567);
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
  for (let i = 0; i < 6; i++) state[i] = W[i]!;
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

/**
 * Writes the bit length little-endian before `end`, with no `DataView` to move a buffer off-heap.
 *
 * @param out - The block or padding being written.
 * @param end - Where the length field ends.
 * @param length - Bytes hashed.
 */
function writeLength(out: Uint8Array, end: number, length: number): void {
  const low = (length % 0x2000_0000) * 8;
  const high = Math.floor(length / 0x2000_0000);
  for (let i = 0; i < 4; i++) {
    out[end - 8 + i] = low >>> (8 * i);
    out[end - 4 + i] = high >>> (8 * i);
  }
}

/** Tiger, the original: 192 bits, three passes, 0x01 padding and little-endian words. */
export class TigerHasher extends ResumableHasher {
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

  update(data: Uint8Array): this {
    assertBytes(data, "data");
    const { buffer } = this;
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
      this.compressBlock(buffer, 0);
      position = 0;
    }
    for (; length - offset >= BLOCK; offset += BLOCK) this.compressBlock(data, offset);
    while (offset < length) buffer[position++] = data[offset++]!;
    this.position = position;
    return this;
  }

  digestInto(out: Uint8Array): void {
    const { buffer } = this;
    let position = this.position;
    buffer[position++] = MARKER;
    if (position > LENGTH_FIELD) {
      buffer.fill(0, position);
      this.compressBlock(buffer, 0);
      position = 0;
    }
    buffer.fill(0, position, LENGTH_FIELD);
    writeLength(buffer, BLOCK, this.length);
    this.compressBlock(buffer, 0);
    wordsToBytes(this.state, out, this.outputLength, true);
  }

  padding(length: number): Uint8Array {
    const size = 9 + ((BLOCK - ((length + 9) % BLOCK)) % BLOCK);
    const out = new Uint8Array(size);
    out[0] = MARKER;
    writeLength(out, size, length);
    return out;
  }

  resume(digest: Uint8Array, length: number): this {
    assertBytes(digest, "digest");
    const { state } = this;
    if (digest.length !== this.outputLength || !(length >= 0 && length % BLOCK === 0)) {
      throw new HashError(
        `resume takes a ${this.outputLength}-byte digest and a multiple of ${BLOCK} bytes`,
      );
    }
    const view = viewOf(digest);
    for (let i = 0; i < state.length; i++) state[i] = view.getInt32(i * 4, true);
    this.position = 0;
    this.length = length;
    return this;
  }

  load(source: this): this {
    this.state.set(source.state);
    this.buffer.set(source.buffer);
    this.position = source.position;
    this.length = source.length;
    return this;
  }

  /**
   * Compresses a block, building the S-boxes first, so a hasher made only to be listed is free.
   *
   * @param block - Bytes holding the block.
   * @param offset - Where the block starts.
   */
  private compressBlock(block: Uint8Array, offset: number): void {
    if (!built) build();
    compress(this.state, block, offset);
  }
}
