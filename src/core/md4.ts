/** MD4 (RFC 1320): little-endian words, three rounds of sixteen steps. */
import { MerkleDamgard } from "./hasher.ts";

/** Word each step of the second round reads. */
const R2 = /* @__PURE__ */ new Uint8Array([0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15]);

/** Word each step of the third round reads. */
const R3 = /* @__PURE__ */ new Uint8Array([0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15]);

/** Left rotations of the four steps that repeat through each round, round by round. */
const S = /* @__PURE__ */ new Uint8Array([3, 7, 11, 19, 3, 5, 9, 13, 3, 9, 11, 15]);

/** The block's words, shared: hashing is synchronous. */
const X = new Int32Array(16);

/** MD4. */
export class Md4Hasher extends MerkleDamgard {
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
    for (let i = 0; i < 16; i++) {
      f = (a + ((b & c) | (~b & d)) + x[i]!) | 0;
      r = S[i & 3]!;
      a = d;
      d = c;
      c = b;
      b = (f << r) | (f >>> (32 - r));
    }
    for (let i = 0; i < 16; i++) {
      f = (a + ((b & c) | (b & d) | (c & d)) + x[R2[i]!]! + 0x5a827999) | 0;
      r = S[4 + (i & 3)]!;
      a = d;
      d = c;
      c = b;
      b = (f << r) | (f >>> (32 - r));
    }
    for (let i = 0; i < 16; i++) {
      f = (a + (b ^ c ^ d) + x[R3[i]!]! + 0x6ed9eba1) | 0;
      r = S[8 + (i & 3)]!;
      a = d;
      d = c;
      c = b;
      b = (f << r) | (f >>> (32 - r));
    }
    s[0] = (s[0]! + a) | 0;
    s[1] = (s[1]! + b) | 0;
    s[2] = (s[2]! + c) | 0;
    s[3] = (s[3]! + d) | 0;
  }
}

/**
 * MD4 of the input.
 *
 * @param data - Bytes to hash.
 * @returns {Uint8Array} 16 bytes.
 */
export function md4(data: Uint8Array): Uint8Array {
  return new Md4Hasher().update(data).digest();
}
