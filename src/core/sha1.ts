/** SHA-1 (FIPS 180-4): big-endian words, eighty steps. */
import { MerkleDamgard } from "./hasher.ts";

/** Message schedule scratch, shared: hashing is synchronous. */
const W = new Int32Array(80);

/** SHA-1. */
export class Sha1Hasher extends MerkleDamgard {
  protected readonly state = new Int32Array([
    0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0,
  ]);

  constructor() {
    super(64, 20, false);
  }

  protected compress(view: DataView, offset: number): void {
    const s = this.state;
    const w = W;
    for (let i = 0; i < 16; i++) w[i] = view.getInt32(offset + i * 4);
    for (let i = 16; i < 80; i++) {
      const x = w[i - 3]! ^ w[i - 8]! ^ w[i - 14]! ^ w[i - 16]!;
      w[i] = (x << 1) | (x >>> 31);
    }
    let a = s[0]!;
    let b = s[1]!;
    let c = s[2]!;
    let d = s[3]!;
    let e = s[4]!;
    let f = 0;
    // One loop per round, each with its function and constant written out.
    for (let i = 0; i < 20; i++) {
      f = (((b & c) | (~b & d)) + 0x5a827999 + ((a << 5) | (a >>> 27)) + e + w[i]!) | 0;
      e = d;
      d = c;
      c = (b << 30) | (b >>> 2);
      b = a;
      a = f;
    }
    for (let i = 20; i < 40; i++) {
      f = ((b ^ c ^ d) + 0x6ed9eba1 + ((a << 5) | (a >>> 27)) + e + w[i]!) | 0;
      e = d;
      d = c;
      c = (b << 30) | (b >>> 2);
      b = a;
      a = f;
    }
    for (let i = 40; i < 60; i++) {
      f = (((b & c) | (b & d) | (c & d)) - 0x70e44324 + ((a << 5) | (a >>> 27)) + e + w[i]!) | 0;
      e = d;
      d = c;
      c = (b << 30) | (b >>> 2);
      b = a;
      a = f;
    }
    for (let i = 60; i < 80; i++) {
      f = ((b ^ c ^ d) - 0x359d3e2a + ((a << 5) | (a >>> 27)) + e + w[i]!) | 0;
      e = d;
      d = c;
      c = (b << 30) | (b >>> 2);
      b = a;
      a = f;
    }
    s[0] = (s[0]! + a) | 0;
    s[1] = (s[1]! + b) | 0;
    s[2] = (s[2]! + c) | 0;
    s[3] = (s[3]! + d) | 0;
    s[4] = (s[4]! + e) | 0;
  }
}
