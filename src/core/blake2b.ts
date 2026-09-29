/**
 * BLAKE2b (RFC 7693) with any output length from 1 to 64 bytes: 64 for plain `blake2b`, 32 on
 * Sui, 28 for Cardano key hashes. No key, salt or personalization. Words are 64-bit, held as low
 * and high 32-bit halves.
 */
import { Blake2 } from "./hasher.ts";

/** SHA-512's initial values, which BLAKE2b shares, as low and high halves. */
const IV = new Uint32Array([
  0xf3bcc908, 0x6a09e667, 0x84caa73b, 0xbb67ae85, 0xfe94f82b, 0x3c6ef372, 0x5f1d36f1, 0xa54ff53a,
  0xade682d1, 0x510e527f, 0x2b3e6c1f, 0x9b05688c, 0xfb41bd6b, 0x1f83d9ab, 0x137e2179, 0x5be0cd19,
]);

/**
 * The message word each of the twelve rounds feeds each G call, as indices of low halves.
 * Rounds 11 and 12 repeat the first two permutations.
 */
const SCHEDULE = new Uint8Array([
  0, 2, 4, 6, 8, 10, 12, 14, 16, 18, 20, 22, 24, 26, 28, 30, 28, 20, 8, 16, 18, 30, 26, 12, 2, 24,
  0, 4, 22, 14, 10, 6, 22, 16, 24, 0, 10, 4, 30, 26, 20, 28, 6, 12, 14, 2, 18, 8, 14, 18, 6, 2, 26,
  24, 22, 28, 4, 12, 10, 20, 8, 0, 30, 16, 18, 0, 10, 14, 4, 8, 20, 30, 28, 2, 22, 24, 12, 16, 6,
  26, 4, 24, 12, 20, 0, 22, 16, 6, 8, 26, 14, 10, 30, 28, 2, 18, 24, 10, 2, 30, 28, 26, 8, 20, 0,
  14, 12, 6, 18, 4, 16, 22, 26, 22, 14, 28, 24, 2, 6, 18, 10, 0, 30, 8, 16, 12, 4, 20, 12, 30, 28,
  18, 22, 6, 0, 16, 24, 4, 26, 14, 2, 8, 20, 10, 20, 4, 16, 8, 14, 12, 2, 10, 30, 22, 18, 28, 6, 24,
  26, 0, 0, 2, 4, 6, 8, 10, 12, 14, 16, 18, 20, 22, 24, 26, 28, 30, 28, 20, 8, 16, 18, 30, 26, 12,
  2, 24, 0, 4, 22, 14, 10, 6,
]);

/**
 * Compresses one 128-byte block into the state. One round is unrolled and loops twelve times;
 * each 64-bit word lives in two locals, `lN` (low) and `hN` (high). An addition carries into the
 * high half the top bit of `(a & b) | ((a | b) & ~sum)`, which keeps every value an int32.
 *
 * @param h - Chained state, sixteen halves, updated in place.
 * @param m - The block as thirty-two little-endian halves.
 * @param counter - Bytes hashed through this block.
 * @param last - Whether this is the final block.
 */
function compress(h: Int32Array, m: Int32Array, counter: number, last: boolean): void {
  let l0 = h[0]! | 0;
  let h0 = h[1]! | 0;
  let l1 = h[2]! | 0;
  let h1 = h[3]! | 0;
  let l2 = h[4]! | 0;
  let h2 = h[5]! | 0;
  let l3 = h[6]! | 0;
  let h3 = h[7]! | 0;
  let l4 = h[8]! | 0;
  let h4 = h[9]! | 0;
  let l5 = h[10]! | 0;
  let h5 = h[11]! | 0;
  let l6 = h[12]! | 0;
  let h6 = h[13]! | 0;
  let l7 = h[14]! | 0;
  let h7 = h[15]! | 0;
  let l8 = IV[0]! | 0;
  let h8 = IV[1]! | 0;
  let l9 = IV[2]! | 0;
  let h9 = IV[3]! | 0;
  let l10 = IV[4]! | 0;
  let h10 = IV[5]! | 0;
  let l11 = IV[6]! | 0;
  let h11 = IV[7]! | 0;
  let l12 = (IV[8]! ^ (counter >>> 0)) | 0;
  let h12 = (IV[9]! ^ Math.floor(counter / 0x1_0000_0000)) | 0;
  let l13 = IV[10]! | 0;
  let h13 = IV[11]! | 0;
  let l14 = (last ? ~IV[12]! : IV[12]!) | 0;
  let h14 = (last ? ~IV[13]! : IV[13]!) | 0;
  let l15 = IV[14]! | 0;
  let h15 = IV[15]! | 0;
  let t = 0;
  let x = 0;
  let y = 0;
  let i = 0;
  let w = 0;
  for (let s = 0; s < 192; s += 16) {
    t = (l0 + l4) | 0;
    h0 = (h0 + h4 + (((l0 & l4) | ((l0 | l4) & ~t)) >>> 31)) | 0;
    l0 = t;
    i = SCHEDULE[s + 0]!;
    w = m[i]!;
    t = (l0 + w) | 0;
    h0 = (h0 + m[i + 1]! + (((l0 & w) | ((l0 | w) & ~t)) >>> 31)) | 0;
    l0 = t;
    x = l12 ^ l0;
    l12 = h12 ^ h0;
    h12 = x;
    t = (l8 + l12) | 0;
    h8 = (h8 + h12 + (((l8 & l12) | ((l8 | l12) & ~t)) >>> 31)) | 0;
    l8 = t;
    x = l4 ^ l8;
    y = h4 ^ h8;
    l4 = (x >>> 24) | (y << 8);
    h4 = (y >>> 24) | (x << 8);
    t = (l0 + l4) | 0;
    h0 = (h0 + h4 + (((l0 & l4) | ((l0 | l4) & ~t)) >>> 31)) | 0;
    l0 = t;
    i = SCHEDULE[s + 1]!;
    w = m[i]!;
    t = (l0 + w) | 0;
    h0 = (h0 + m[i + 1]! + (((l0 & w) | ((l0 | w) & ~t)) >>> 31)) | 0;
    l0 = t;
    x = l12 ^ l0;
    y = h12 ^ h0;
    l12 = (x >>> 16) | (y << 16);
    h12 = (y >>> 16) | (x << 16);
    t = (l8 + l12) | 0;
    h8 = (h8 + h12 + (((l8 & l12) | ((l8 | l12) & ~t)) >>> 31)) | 0;
    l8 = t;
    x = l4 ^ l8;
    y = h4 ^ h8;
    l4 = (x << 1) | (y >>> 31);
    h4 = (y << 1) | (x >>> 31);
    t = (l1 + l5) | 0;
    h1 = (h1 + h5 + (((l1 & l5) | ((l1 | l5) & ~t)) >>> 31)) | 0;
    l1 = t;
    i = SCHEDULE[s + 2]!;
    w = m[i]!;
    t = (l1 + w) | 0;
    h1 = (h1 + m[i + 1]! + (((l1 & w) | ((l1 | w) & ~t)) >>> 31)) | 0;
    l1 = t;
    x = l13 ^ l1;
    l13 = h13 ^ h1;
    h13 = x;
    t = (l9 + l13) | 0;
    h9 = (h9 + h13 + (((l9 & l13) | ((l9 | l13) & ~t)) >>> 31)) | 0;
    l9 = t;
    x = l5 ^ l9;
    y = h5 ^ h9;
    l5 = (x >>> 24) | (y << 8);
    h5 = (y >>> 24) | (x << 8);
    t = (l1 + l5) | 0;
    h1 = (h1 + h5 + (((l1 & l5) | ((l1 | l5) & ~t)) >>> 31)) | 0;
    l1 = t;
    i = SCHEDULE[s + 3]!;
    w = m[i]!;
    t = (l1 + w) | 0;
    h1 = (h1 + m[i + 1]! + (((l1 & w) | ((l1 | w) & ~t)) >>> 31)) | 0;
    l1 = t;
    x = l13 ^ l1;
    y = h13 ^ h1;
    l13 = (x >>> 16) | (y << 16);
    h13 = (y >>> 16) | (x << 16);
    t = (l9 + l13) | 0;
    h9 = (h9 + h13 + (((l9 & l13) | ((l9 | l13) & ~t)) >>> 31)) | 0;
    l9 = t;
    x = l5 ^ l9;
    y = h5 ^ h9;
    l5 = (x << 1) | (y >>> 31);
    h5 = (y << 1) | (x >>> 31);
    t = (l2 + l6) | 0;
    h2 = (h2 + h6 + (((l2 & l6) | ((l2 | l6) & ~t)) >>> 31)) | 0;
    l2 = t;
    i = SCHEDULE[s + 4]!;
    w = m[i]!;
    t = (l2 + w) | 0;
    h2 = (h2 + m[i + 1]! + (((l2 & w) | ((l2 | w) & ~t)) >>> 31)) | 0;
    l2 = t;
    x = l14 ^ l2;
    l14 = h14 ^ h2;
    h14 = x;
    t = (l10 + l14) | 0;
    h10 = (h10 + h14 + (((l10 & l14) | ((l10 | l14) & ~t)) >>> 31)) | 0;
    l10 = t;
    x = l6 ^ l10;
    y = h6 ^ h10;
    l6 = (x >>> 24) | (y << 8);
    h6 = (y >>> 24) | (x << 8);
    t = (l2 + l6) | 0;
    h2 = (h2 + h6 + (((l2 & l6) | ((l2 | l6) & ~t)) >>> 31)) | 0;
    l2 = t;
    i = SCHEDULE[s + 5]!;
    w = m[i]!;
    t = (l2 + w) | 0;
    h2 = (h2 + m[i + 1]! + (((l2 & w) | ((l2 | w) & ~t)) >>> 31)) | 0;
    l2 = t;
    x = l14 ^ l2;
    y = h14 ^ h2;
    l14 = (x >>> 16) | (y << 16);
    h14 = (y >>> 16) | (x << 16);
    t = (l10 + l14) | 0;
    h10 = (h10 + h14 + (((l10 & l14) | ((l10 | l14) & ~t)) >>> 31)) | 0;
    l10 = t;
    x = l6 ^ l10;
    y = h6 ^ h10;
    l6 = (x << 1) | (y >>> 31);
    h6 = (y << 1) | (x >>> 31);
    t = (l3 + l7) | 0;
    h3 = (h3 + h7 + (((l3 & l7) | ((l3 | l7) & ~t)) >>> 31)) | 0;
    l3 = t;
    i = SCHEDULE[s + 6]!;
    w = m[i]!;
    t = (l3 + w) | 0;
    h3 = (h3 + m[i + 1]! + (((l3 & w) | ((l3 | w) & ~t)) >>> 31)) | 0;
    l3 = t;
    x = l15 ^ l3;
    l15 = h15 ^ h3;
    h15 = x;
    t = (l11 + l15) | 0;
    h11 = (h11 + h15 + (((l11 & l15) | ((l11 | l15) & ~t)) >>> 31)) | 0;
    l11 = t;
    x = l7 ^ l11;
    y = h7 ^ h11;
    l7 = (x >>> 24) | (y << 8);
    h7 = (y >>> 24) | (x << 8);
    t = (l3 + l7) | 0;
    h3 = (h3 + h7 + (((l3 & l7) | ((l3 | l7) & ~t)) >>> 31)) | 0;
    l3 = t;
    i = SCHEDULE[s + 7]!;
    w = m[i]!;
    t = (l3 + w) | 0;
    h3 = (h3 + m[i + 1]! + (((l3 & w) | ((l3 | w) & ~t)) >>> 31)) | 0;
    l3 = t;
    x = l15 ^ l3;
    y = h15 ^ h3;
    l15 = (x >>> 16) | (y << 16);
    h15 = (y >>> 16) | (x << 16);
    t = (l11 + l15) | 0;
    h11 = (h11 + h15 + (((l11 & l15) | ((l11 | l15) & ~t)) >>> 31)) | 0;
    l11 = t;
    x = l7 ^ l11;
    y = h7 ^ h11;
    l7 = (x << 1) | (y >>> 31);
    h7 = (y << 1) | (x >>> 31);
    t = (l0 + l5) | 0;
    h0 = (h0 + h5 + (((l0 & l5) | ((l0 | l5) & ~t)) >>> 31)) | 0;
    l0 = t;
    i = SCHEDULE[s + 8]!;
    w = m[i]!;
    t = (l0 + w) | 0;
    h0 = (h0 + m[i + 1]! + (((l0 & w) | ((l0 | w) & ~t)) >>> 31)) | 0;
    l0 = t;
    x = l15 ^ l0;
    l15 = h15 ^ h0;
    h15 = x;
    t = (l10 + l15) | 0;
    h10 = (h10 + h15 + (((l10 & l15) | ((l10 | l15) & ~t)) >>> 31)) | 0;
    l10 = t;
    x = l5 ^ l10;
    y = h5 ^ h10;
    l5 = (x >>> 24) | (y << 8);
    h5 = (y >>> 24) | (x << 8);
    t = (l0 + l5) | 0;
    h0 = (h0 + h5 + (((l0 & l5) | ((l0 | l5) & ~t)) >>> 31)) | 0;
    l0 = t;
    i = SCHEDULE[s + 9]!;
    w = m[i]!;
    t = (l0 + w) | 0;
    h0 = (h0 + m[i + 1]! + (((l0 & w) | ((l0 | w) & ~t)) >>> 31)) | 0;
    l0 = t;
    x = l15 ^ l0;
    y = h15 ^ h0;
    l15 = (x >>> 16) | (y << 16);
    h15 = (y >>> 16) | (x << 16);
    t = (l10 + l15) | 0;
    h10 = (h10 + h15 + (((l10 & l15) | ((l10 | l15) & ~t)) >>> 31)) | 0;
    l10 = t;
    x = l5 ^ l10;
    y = h5 ^ h10;
    l5 = (x << 1) | (y >>> 31);
    h5 = (y << 1) | (x >>> 31);
    t = (l1 + l6) | 0;
    h1 = (h1 + h6 + (((l1 & l6) | ((l1 | l6) & ~t)) >>> 31)) | 0;
    l1 = t;
    i = SCHEDULE[s + 10]!;
    w = m[i]!;
    t = (l1 + w) | 0;
    h1 = (h1 + m[i + 1]! + (((l1 & w) | ((l1 | w) & ~t)) >>> 31)) | 0;
    l1 = t;
    x = l12 ^ l1;
    l12 = h12 ^ h1;
    h12 = x;
    t = (l11 + l12) | 0;
    h11 = (h11 + h12 + (((l11 & l12) | ((l11 | l12) & ~t)) >>> 31)) | 0;
    l11 = t;
    x = l6 ^ l11;
    y = h6 ^ h11;
    l6 = (x >>> 24) | (y << 8);
    h6 = (y >>> 24) | (x << 8);
    t = (l1 + l6) | 0;
    h1 = (h1 + h6 + (((l1 & l6) | ((l1 | l6) & ~t)) >>> 31)) | 0;
    l1 = t;
    i = SCHEDULE[s + 11]!;
    w = m[i]!;
    t = (l1 + w) | 0;
    h1 = (h1 + m[i + 1]! + (((l1 & w) | ((l1 | w) & ~t)) >>> 31)) | 0;
    l1 = t;
    x = l12 ^ l1;
    y = h12 ^ h1;
    l12 = (x >>> 16) | (y << 16);
    h12 = (y >>> 16) | (x << 16);
    t = (l11 + l12) | 0;
    h11 = (h11 + h12 + (((l11 & l12) | ((l11 | l12) & ~t)) >>> 31)) | 0;
    l11 = t;
    x = l6 ^ l11;
    y = h6 ^ h11;
    l6 = (x << 1) | (y >>> 31);
    h6 = (y << 1) | (x >>> 31);
    t = (l2 + l7) | 0;
    h2 = (h2 + h7 + (((l2 & l7) | ((l2 | l7) & ~t)) >>> 31)) | 0;
    l2 = t;
    i = SCHEDULE[s + 12]!;
    w = m[i]!;
    t = (l2 + w) | 0;
    h2 = (h2 + m[i + 1]! + (((l2 & w) | ((l2 | w) & ~t)) >>> 31)) | 0;
    l2 = t;
    x = l13 ^ l2;
    l13 = h13 ^ h2;
    h13 = x;
    t = (l8 + l13) | 0;
    h8 = (h8 + h13 + (((l8 & l13) | ((l8 | l13) & ~t)) >>> 31)) | 0;
    l8 = t;
    x = l7 ^ l8;
    y = h7 ^ h8;
    l7 = (x >>> 24) | (y << 8);
    h7 = (y >>> 24) | (x << 8);
    t = (l2 + l7) | 0;
    h2 = (h2 + h7 + (((l2 & l7) | ((l2 | l7) & ~t)) >>> 31)) | 0;
    l2 = t;
    i = SCHEDULE[s + 13]!;
    w = m[i]!;
    t = (l2 + w) | 0;
    h2 = (h2 + m[i + 1]! + (((l2 & w) | ((l2 | w) & ~t)) >>> 31)) | 0;
    l2 = t;
    x = l13 ^ l2;
    y = h13 ^ h2;
    l13 = (x >>> 16) | (y << 16);
    h13 = (y >>> 16) | (x << 16);
    t = (l8 + l13) | 0;
    h8 = (h8 + h13 + (((l8 & l13) | ((l8 | l13) & ~t)) >>> 31)) | 0;
    l8 = t;
    x = l7 ^ l8;
    y = h7 ^ h8;
    l7 = (x << 1) | (y >>> 31);
    h7 = (y << 1) | (x >>> 31);
    t = (l3 + l4) | 0;
    h3 = (h3 + h4 + (((l3 & l4) | ((l3 | l4) & ~t)) >>> 31)) | 0;
    l3 = t;
    i = SCHEDULE[s + 14]!;
    w = m[i]!;
    t = (l3 + w) | 0;
    h3 = (h3 + m[i + 1]! + (((l3 & w) | ((l3 | w) & ~t)) >>> 31)) | 0;
    l3 = t;
    x = l14 ^ l3;
    l14 = h14 ^ h3;
    h14 = x;
    t = (l9 + l14) | 0;
    h9 = (h9 + h14 + (((l9 & l14) | ((l9 | l14) & ~t)) >>> 31)) | 0;
    l9 = t;
    x = l4 ^ l9;
    y = h4 ^ h9;
    l4 = (x >>> 24) | (y << 8);
    h4 = (y >>> 24) | (x << 8);
    t = (l3 + l4) | 0;
    h3 = (h3 + h4 + (((l3 & l4) | ((l3 | l4) & ~t)) >>> 31)) | 0;
    l3 = t;
    i = SCHEDULE[s + 15]!;
    w = m[i]!;
    t = (l3 + w) | 0;
    h3 = (h3 + m[i + 1]! + (((l3 & w) | ((l3 | w) & ~t)) >>> 31)) | 0;
    l3 = t;
    x = l14 ^ l3;
    y = h14 ^ h3;
    l14 = (x >>> 16) | (y << 16);
    h14 = (y >>> 16) | (x << 16);
    t = (l9 + l14) | 0;
    h9 = (h9 + h14 + (((l9 & l14) | ((l9 | l14) & ~t)) >>> 31)) | 0;
    l9 = t;
    x = l4 ^ l9;
    y = h4 ^ h9;
    l4 = (x << 1) | (y >>> 31);
    h4 = (y << 1) | (x >>> 31);
  }
  h[0] = h[0]! ^ l0 ^ l8;
  h[1] = h[1]! ^ h0 ^ h8;
  h[2] = h[2]! ^ l1 ^ l9;
  h[3] = h[3]! ^ h1 ^ h9;
  h[4] = h[4]! ^ l2 ^ l10;
  h[5] = h[5]! ^ h2 ^ h10;
  h[6] = h[6]! ^ l3 ^ l11;
  h[7] = h[7]! ^ h3 ^ h11;
  h[8] = h[8]! ^ l4 ^ l12;
  h[9] = h[9]! ^ h4 ^ h12;
  h[10] = h[10]! ^ l5 ^ l13;
  h[11] = h[11]! ^ h5 ^ h13;
  h[12] = h[12]! ^ l6 ^ l14;
  h[13] = h[13]! ^ h6 ^ h14;
  h[14] = h[14]! ^ l7 ^ l15;
  h[15] = h[15]! ^ h7 ^ h15;
}

if (new Uint8Array(new Uint32Array([1]).buffer)[0] !== 1) {
  throw new Error("BLAKE2b here reads blocks and the state as little-endian bytes");
}

/** BLAKE2b with an output of 1 to 64 bytes and no key, salt or personalization. */
export class Blake2bHasher extends Blake2 {
  protected readonly state = new Int32Array(16);
  /** The block buffer as thirty-two little-endian halves. */
  private readonly words = new Int32Array(this.block.buffer);

  /**
   * @param outputLength - Digest bytes, 1 to 64.
   */
  constructor(outputLength: number) {
    super(128, outputLength);
    this.state.set(IV);
    // Parameter block: digest length, no key, fanout 1, depth 1.
    this.state[0] = this.state[0]! ^ (0x01010000 | outputLength);
  }

  protected compress(counter: number, last: boolean): void {
    compress(this.state, this.words, counter, last);
  }
}

/**
 * Computes BLAKE2b with the given output length.
 *
 * @param data - Bytes to hash.
 * @param length - Output bytes, 1 to 64.
 * @returns {Uint8Array} The digest.
 */
export function blake2b(data: Uint8Array, length: number): Uint8Array {
  return new Blake2bHasher(length).update(data).digest();
}
