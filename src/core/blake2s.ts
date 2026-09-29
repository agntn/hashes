/**
 * BLAKE2s (RFC 7693) with a 32-byte output and no key, salt or personalization: 32-bit words,
 * ten rounds, 64-byte blocks.
 */
import { Blake2 } from "./hasher.ts";
import { IV256 as IV } from "./sha2.ts";

/** The message word each of the ten rounds feeds each G call. */
const SIGMA = new Uint8Array([
  0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11,
  7, 5, 3, 11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4, 7, 9, 3, 1, 13, 12, 11, 14, 2, 6,
  5, 10, 4, 0, 15, 8, 9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13, 2, 12, 6, 10, 0, 11, 8,
  3, 4, 13, 7, 5, 15, 14, 1, 9, 12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11, 13, 11, 7, 14,
  12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10, 6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5, 10,
  2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0,
]);

/** The block's words, shared: hashing is synchronous. */
const M = new Int32Array(16);

/**
 * Compresses one 64-byte block into the state. The working vector lives in sixteen locals and
 * each round inlines its eight G calls, with the message words picked through `SIGMA`.
 *
 * @param h - Chained state, eight words, updated in place.
 * @param block - A view over the block.
 * @param counter - Bytes hashed through this block.
 * @param last - Whether this is the final block.
 */
function compress(h: Int32Array, block: DataView, counter: number, last: boolean): void {
  const m = M;
  for (let i = 0; i < 16; i++) m[i] = block.getInt32(i * 4, true);
  let v0 = h[0]!;
  let v1 = h[1]!;
  let v2 = h[2]!;
  let v3 = h[3]!;
  let v4 = h[4]!;
  let v5 = h[5]!;
  let v6 = h[6]!;
  let v7 = h[7]!;
  let v8 = IV[0]!;
  let v9 = IV[1]!;
  let v10 = IV[2]!;
  let v11 = IV[3]!;
  let v12 = IV[4]! ^ counter;
  let v13 = IV[5]! ^ Math.floor(counter / 0x1_0000_0000);
  let v14 = last ? ~IV[6]! : IV[6]!;
  let v15 = IV[7]!;
  for (let s = 0; s < 160; s += 16) {
    v0 = (v0 + v4 + m[SIGMA[s + 0]!]!) | 0;
    v12 ^= v0;
    v12 = (v12 >>> 16) | (v12 << 16);
    v8 = (v8 + v12) | 0;
    v4 ^= v8;
    v4 = (v4 >>> 12) | (v4 << 20);
    v0 = (v0 + v4 + m[SIGMA[s + 1]!]!) | 0;
    v12 ^= v0;
    v12 = (v12 >>> 8) | (v12 << 24);
    v8 = (v8 + v12) | 0;
    v4 ^= v8;
    v4 = (v4 >>> 7) | (v4 << 25);
    v1 = (v1 + v5 + m[SIGMA[s + 2]!]!) | 0;
    v13 ^= v1;
    v13 = (v13 >>> 16) | (v13 << 16);
    v9 = (v9 + v13) | 0;
    v5 ^= v9;
    v5 = (v5 >>> 12) | (v5 << 20);
    v1 = (v1 + v5 + m[SIGMA[s + 3]!]!) | 0;
    v13 ^= v1;
    v13 = (v13 >>> 8) | (v13 << 24);
    v9 = (v9 + v13) | 0;
    v5 ^= v9;
    v5 = (v5 >>> 7) | (v5 << 25);
    v2 = (v2 + v6 + m[SIGMA[s + 4]!]!) | 0;
    v14 ^= v2;
    v14 = (v14 >>> 16) | (v14 << 16);
    v10 = (v10 + v14) | 0;
    v6 ^= v10;
    v6 = (v6 >>> 12) | (v6 << 20);
    v2 = (v2 + v6 + m[SIGMA[s + 5]!]!) | 0;
    v14 ^= v2;
    v14 = (v14 >>> 8) | (v14 << 24);
    v10 = (v10 + v14) | 0;
    v6 ^= v10;
    v6 = (v6 >>> 7) | (v6 << 25);
    v3 = (v3 + v7 + m[SIGMA[s + 6]!]!) | 0;
    v15 ^= v3;
    v15 = (v15 >>> 16) | (v15 << 16);
    v11 = (v11 + v15) | 0;
    v7 ^= v11;
    v7 = (v7 >>> 12) | (v7 << 20);
    v3 = (v3 + v7 + m[SIGMA[s + 7]!]!) | 0;
    v15 ^= v3;
    v15 = (v15 >>> 8) | (v15 << 24);
    v11 = (v11 + v15) | 0;
    v7 ^= v11;
    v7 = (v7 >>> 7) | (v7 << 25);
    v0 = (v0 + v5 + m[SIGMA[s + 8]!]!) | 0;
    v15 ^= v0;
    v15 = (v15 >>> 16) | (v15 << 16);
    v10 = (v10 + v15) | 0;
    v5 ^= v10;
    v5 = (v5 >>> 12) | (v5 << 20);
    v0 = (v0 + v5 + m[SIGMA[s + 9]!]!) | 0;
    v15 ^= v0;
    v15 = (v15 >>> 8) | (v15 << 24);
    v10 = (v10 + v15) | 0;
    v5 ^= v10;
    v5 = (v5 >>> 7) | (v5 << 25);
    v1 = (v1 + v6 + m[SIGMA[s + 10]!]!) | 0;
    v12 ^= v1;
    v12 = (v12 >>> 16) | (v12 << 16);
    v11 = (v11 + v12) | 0;
    v6 ^= v11;
    v6 = (v6 >>> 12) | (v6 << 20);
    v1 = (v1 + v6 + m[SIGMA[s + 11]!]!) | 0;
    v12 ^= v1;
    v12 = (v12 >>> 8) | (v12 << 24);
    v11 = (v11 + v12) | 0;
    v6 ^= v11;
    v6 = (v6 >>> 7) | (v6 << 25);
    v2 = (v2 + v7 + m[SIGMA[s + 12]!]!) | 0;
    v13 ^= v2;
    v13 = (v13 >>> 16) | (v13 << 16);
    v8 = (v8 + v13) | 0;
    v7 ^= v8;
    v7 = (v7 >>> 12) | (v7 << 20);
    v2 = (v2 + v7 + m[SIGMA[s + 13]!]!) | 0;
    v13 ^= v2;
    v13 = (v13 >>> 8) | (v13 << 24);
    v8 = (v8 + v13) | 0;
    v7 ^= v8;
    v7 = (v7 >>> 7) | (v7 << 25);
    v3 = (v3 + v4 + m[SIGMA[s + 14]!]!) | 0;
    v14 ^= v3;
    v14 = (v14 >>> 16) | (v14 << 16);
    v9 = (v9 + v14) | 0;
    v4 ^= v9;
    v4 = (v4 >>> 12) | (v4 << 20);
    v3 = (v3 + v4 + m[SIGMA[s + 15]!]!) | 0;
    v14 ^= v3;
    v14 = (v14 >>> 8) | (v14 << 24);
    v9 = (v9 + v14) | 0;
    v4 ^= v9;
    v4 = (v4 >>> 7) | (v4 << 25);
  }
  h[0] = h[0]! ^ v0 ^ v8;
  h[1] = h[1]! ^ v1 ^ v9;
  h[2] = h[2]! ^ v2 ^ v10;
  h[3] = h[3]! ^ v3 ^ v11;
  h[4] = h[4]! ^ v4 ^ v12;
  h[5] = h[5]! ^ v5 ^ v13;
  h[6] = h[6]! ^ v6 ^ v14;
  h[7] = h[7]! ^ v7 ^ v15;
}

/** BLAKE2s-256. */
export class Blake2sHasher extends Blake2 {
  protected readonly state = IV.slice();
  private readonly view = new DataView(this.block.buffer);

  constructor() {
    super(64, 32);
    // Parameter block: 32-byte digest, no key, fanout 1, depth 1.
    this.state[0] = this.state[0]! ^ 0x01010020;
  }

  protected compress(counter: number, last: boolean): void {
    compress(this.state, this.view, counter, last);
  }
}
