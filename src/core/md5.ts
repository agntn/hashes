/** MD5 (RFC 1321): little-endian words, four rounds of sixteen steps. */
import { MerkleDamgard } from "./hasher.ts";

/** The constant of each step, from the sine table. */
const K = /* @__PURE__ */ new Int32Array([
  0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
  0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
  0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
  0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
  0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
  0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
  0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
  0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391,
]);

/** Left rotation of each step. */
const S = /* @__PURE__ */ new Uint8Array([
  7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14,
  20, 5, 9, 14, 20, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 6, 10, 15, 21, 6,
  10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
]);

/** The block's words, shared: hashing is synchronous. */
const X = new Int32Array(16);

/** MD5. */
export class Md5Hasher extends MerkleDamgard {
  protected readonly state = new Int32Array([0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476]);

  constructor() {
    super(64, 16, true);
  }

  protected compress(view: DataView, offset: number): void {
    const s = this.state;
    const x = X;
    for (let i = 0; i < 16; i++) x[i] = view.getInt32(offset + i * 4, true);
    let a = s[0]!;
    let b = s[1]!;
    let c = s[2]!;
    let d = s[3]!;
    let f = 0;
    let r = 0;
    // One loop per round, each with its function and word order written out.
    for (let i = 0; i < 16; i++) {
      f = (((b & c) | (~b & d)) + x[i]! + a + K[i]!) | 0;
      r = S[i]!;
      a = d;
      d = c;
      c = b;
      b = (b + ((f << r) | (f >>> (32 - r)))) | 0;
    }
    for (let i = 16; i < 32; i++) {
      f = (((d & b) | (~d & c)) + x[(5 * i + 1) & 15]! + a + K[i]!) | 0;
      r = S[i]!;
      a = d;
      d = c;
      c = b;
      b = (b + ((f << r) | (f >>> (32 - r)))) | 0;
    }
    for (let i = 32; i < 48; i++) {
      f = ((b ^ c ^ d) + x[(3 * i + 5) & 15]! + a + K[i]!) | 0;
      r = S[i]!;
      a = d;
      d = c;
      c = b;
      b = (b + ((f << r) | (f >>> (32 - r)))) | 0;
    }
    for (let i = 48; i < 64; i++) {
      f = ((c ^ (b | ~d)) + x[(7 * i) & 15]! + a + K[i]!) | 0;
      r = S[i]!;
      a = d;
      d = c;
      c = b;
      b = (b + ((f << r) | (f >>> (32 - r)))) | 0;
    }
    s[0] = (s[0]! + a) | 0;
    s[1] = (s[1]! + b) | 0;
    s[2] = (s[2]! + c) | 0;
    s[3] = (s[3]! + d) | 0;
  }
}

/**
 * MD5 of the input.
 *
 * @param data - Bytes to hash.
 * @returns {Uint8Array} 16 bytes.
 */
export function md5(data: Uint8Array): Uint8Array {
  return new Md5Hasher().update(data).digest();
}
