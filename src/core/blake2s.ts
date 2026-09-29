/**
 * BLAKE2s (RFC 7693) with a 32-byte output and no key, salt or personalization: 32-bit words,
 * ten rounds, 64-byte blocks.
 */
import { Hasher, viewOf } from "./hasher.ts";

/** SHA-256's initial values, which BLAKE2s shares. */
const IV = new Int32Array([
  0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
]);

/** The message word each of the ten rounds feeds each G call. */
const SIGMA = new Uint8Array([
  0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11,
  7, 5, 3, 11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4, 7, 9, 3, 1, 13, 12, 11, 14, 2, 6,
  5, 10, 4, 0, 15, 8, 9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13, 2, 12, 6, 10, 0, 11, 8,
  3, 4, 13, 7, 5, 15, 14, 1, 9, 12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11, 13, 11, 7, 14,
  12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10, 6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5, 10,
  2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0,
]);

/** The block's words and the working vector, shared: hashing is synchronous. */
const M = new Int32Array(16);
const V = new Int32Array(16);

/**
 * The G mixing function on four words of the working vector.
 *
 * @param v - Working vector, updated in place.
 * @param a - Index of the first word.
 * @param b - Index of the second word.
 * @param c - Index of the third word.
 * @param d - Index of the fourth word.
 * @param x - First message word.
 * @param y - Second message word.
 */
function g(v: Int32Array, a: number, b: number, c: number, d: number, x: number, y: number): void {
  let va = v[a]!;
  let vb = v[b]!;
  let vc = v[c]!;
  let vd = v[d]!;
  va = (va + vb + x) | 0;
  vd ^= va;
  vd = (vd >>> 16) | (vd << 16);
  vc = (vc + vd) | 0;
  vb ^= vc;
  vb = (vb >>> 12) | (vb << 20);
  va = (va + vb + y) | 0;
  vd ^= va;
  vd = (vd >>> 8) | (vd << 24);
  vc = (vc + vd) | 0;
  vb ^= vc;
  vb = (vb >>> 7) | (vb << 25);
  v[a] = va;
  v[b] = vb;
  v[c] = vc;
  v[d] = vd;
}

/**
 * Compresses one 64-byte block into the state.
 *
 * @param h - Chained state, eight words, updated in place.
 * @param block - A view over the block.
 * @param counter - Bytes hashed through this block.
 * @param last - Whether this is the final block.
 */
function compress(h: Int32Array, block: DataView, counter: number, last: boolean): void {
  const m = M;
  const v = V;
  for (let i = 0; i < 16; i++) m[i] = block.getInt32(i * 4, true);
  v.set(h);
  v.set(IV, 8);
  v[12] = IV[4]! ^ counter;
  v[13] = IV[5]! ^ Math.floor(counter / 0x1_0000_0000);
  if (last) v[14] = ~IV[6]!;
  for (let s = 0; s < 160; s += 16) {
    g(v, 0, 4, 8, 12, m[SIGMA[s]!]!, m[SIGMA[s + 1]!]!);
    g(v, 1, 5, 9, 13, m[SIGMA[s + 2]!]!, m[SIGMA[s + 3]!]!);
    g(v, 2, 6, 10, 14, m[SIGMA[s + 4]!]!, m[SIGMA[s + 5]!]!);
    g(v, 3, 7, 11, 15, m[SIGMA[s + 6]!]!, m[SIGMA[s + 7]!]!);
    g(v, 0, 5, 10, 15, m[SIGMA[s + 8]!]!, m[SIGMA[s + 9]!]!);
    g(v, 1, 6, 11, 12, m[SIGMA[s + 10]!]!, m[SIGMA[s + 11]!]!);
    g(v, 2, 7, 8, 13, m[SIGMA[s + 12]!]!, m[SIGMA[s + 13]!]!);
    g(v, 3, 4, 9, 14, m[SIGMA[s + 14]!]!, m[SIGMA[s + 15]!]!);
  }
  for (let i = 0; i < 8; i++) h[i] = h[i]! ^ v[i]! ^ v[i + 8]!;
}

/** BLAKE2s-256. */
export class Blake2sHasher extends Hasher {
  readonly blockLength = 64;
  readonly outputLength = 32;
  private readonly state = IV.slice();
  private readonly block = new Uint8Array(64);
  private readonly view = new DataView(this.block.buffer);
  /** Bytes in the block buffer, which keeps the last block until the digest flags it. */
  private position = 0;
  /** Bytes compressed so far. */
  private counter = 0;

  constructor() {
    super();
    // Parameter block: 32-byte digest, no key, fanout 1, depth 1.
    this.state[0] = this.state[0]! ^ 0x01010020;
  }

  fresh(): this {
    return new Blake2sHasher() as this;
  }

  update(data: Uint8Array): this {
    for (let offset = 0; offset < data.length;) {
      if (this.position === 64) {
        this.counter += 64;
        compress(this.state, this.view, this.counter, false);
        this.position = 0;
      }
      const end = Math.min(data.length, offset + 64 - this.position);
      this.block.set(data.subarray(offset, end), this.position);
      this.position += end - offset;
      offset = end;
    }
    return this;
  }

  digestInto(out: Uint8Array): void {
    this.block.fill(0, this.position);
    compress(this.state, this.view, this.counter + this.position, true);
    const view = viewOf(out);
    for (let i = 0; i < 8; i++) view.setInt32(i * 4, this.state[i]!, true);
  }

  load(source: this): this {
    this.state.set(source.state);
    this.block.set(source.block);
    this.position = source.position;
    this.counter = source.counter;
    return this;
  }
}
