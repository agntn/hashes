/**
 * RIPEMD-160: little-endian words, two parallel lines of five rounds, each round sixteen steps.
 * The right line runs the five boolean functions in reverse order.
 */
import { MerkleDamgard } from "./hasher.ts";
import { sha256 } from "./sha2.ts";

/** Word each step of the left line reads. */
const RL = new Uint8Array([
  0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2,
  14, 11, 8, 3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12, 1, 9, 11, 10, 0, 8, 12, 4, 13, 3,
  7, 15, 14, 5, 6, 2, 4, 0, 5, 9, 7, 12, 2, 10, 14, 1, 3, 8, 11, 6, 15, 13,
]);

/** Word each step of the right line reads. */
const RR = new Uint8Array([
  5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12, 6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12, 4,
  9, 1, 2, 15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13, 8, 6, 4, 1, 3, 11, 15, 0, 5, 12, 2,
  13, 9, 7, 10, 14, 12, 15, 10, 4, 1, 5, 8, 7, 6, 2, 13, 14, 0, 3, 9, 11,
]);

/** Left rotation of each step of the left line. */
const SL = new Uint8Array([
  11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8, 7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15, 9,
  11, 7, 13, 12, 11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5, 11, 12, 14, 15, 14, 15, 9,
  8, 9, 14, 5, 6, 8, 6, 5, 12, 9, 15, 5, 11, 6, 8, 13, 12, 5, 12, 13, 14, 11, 8, 5, 6,
]);

/** Left rotation of each step of the right line. */
const SR = new Uint8Array([
  8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6, 9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12, 7,
  6, 15, 13, 11, 9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5, 15, 5, 8, 11, 14, 14, 6,
  14, 6, 9, 12, 9, 12, 5, 15, 8, 8, 5, 12, 9, 12, 5, 14, 6, 8, 13, 6, 5, 15, 13, 11, 11,
]);

/** The block's words, shared: hashing is synchronous. */
const X = new Int32Array(16);

/** RIPEMD-160. */
export class Ripemd160Hasher extends MerkleDamgard {
  protected readonly state = new Int32Array([
    0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0,
  ]);

  constructor() {
    super(64, 20, true);
  }

  protected compress(view: DataView, offset: number): void {
    const s = this.state;
    const x = X;
    for (let i = 0; i < 16; i++) x[i] = view.getInt32(offset + i * 4, true);
    let al = s[0]!;
    let bl = s[1]!;
    let cl = s[2]!;
    let dl = s[3]!;
    let el = s[4]!;
    let ar = al;
    let br = bl;
    let cr = cl;
    let dr = dl;
    let er = el;
    let t = 0;
    let r = 0;
    // One loop per round, each with its boolean functions written out: the left line runs them
    // in order, the right line in reverse.
    for (let i = 0; i < 16; i++) {
      t = (al + (bl ^ cl ^ dl) + x[RL[i]!]!) | 0;
      r = SL[i]!;
      t = (((t << r) | (t >>> (32 - r))) + el) | 0;
      al = el;
      el = dl;
      dl = (cl << 10) | (cl >>> 22);
      cl = bl;
      bl = t;
      t = (ar + (br ^ (cr | ~dr)) + x[RR[i]!]! + 0x50a28be6) | 0;
      r = SR[i]!;
      t = (((t << r) | (t >>> (32 - r))) + er) | 0;
      ar = er;
      er = dr;
      dr = (cr << 10) | (cr >>> 22);
      cr = br;
      br = t;
    }
    for (let i = 16; i < 32; i++) {
      t = (al + ((bl & cl) | (~bl & dl)) + x[RL[i]!]! + 0x5a827999) | 0;
      r = SL[i]!;
      t = (((t << r) | (t >>> (32 - r))) + el) | 0;
      al = el;
      el = dl;
      dl = (cl << 10) | (cl >>> 22);
      cl = bl;
      bl = t;
      t = (ar + ((br & dr) | (cr & ~dr)) + x[RR[i]!]! + 0x5c4dd124) | 0;
      r = SR[i]!;
      t = (((t << r) | (t >>> (32 - r))) + er) | 0;
      ar = er;
      er = dr;
      dr = (cr << 10) | (cr >>> 22);
      cr = br;
      br = t;
    }
    for (let i = 32; i < 48; i++) {
      t = (al + ((bl | ~cl) ^ dl) + x[RL[i]!]! + 0x6ed9eba1) | 0;
      r = SL[i]!;
      t = (((t << r) | (t >>> (32 - r))) + el) | 0;
      al = el;
      el = dl;
      dl = (cl << 10) | (cl >>> 22);
      cl = bl;
      bl = t;
      t = (ar + ((br | ~cr) ^ dr) + x[RR[i]!]! + 0x6d703ef3) | 0;
      r = SR[i]!;
      t = (((t << r) | (t >>> (32 - r))) + er) | 0;
      ar = er;
      er = dr;
      dr = (cr << 10) | (cr >>> 22);
      cr = br;
      br = t;
    }
    for (let i = 48; i < 64; i++) {
      t = (al + ((bl & dl) | (cl & ~dl)) + x[RL[i]!]! + 0x8f1bbcdc) | 0;
      r = SL[i]!;
      t = (((t << r) | (t >>> (32 - r))) + el) | 0;
      al = el;
      el = dl;
      dl = (cl << 10) | (cl >>> 22);
      cl = bl;
      bl = t;
      t = (ar + ((br & cr) | (~br & dr)) + x[RR[i]!]! + 0x7a6d76e9) | 0;
      r = SR[i]!;
      t = (((t << r) | (t >>> (32 - r))) + er) | 0;
      ar = er;
      er = dr;
      dr = (cr << 10) | (cr >>> 22);
      cr = br;
      br = t;
    }
    for (let i = 64; i < 80; i++) {
      t = (al + (bl ^ (cl | ~dl)) + x[RL[i]!]! + 0xa953fd4e) | 0;
      r = SL[i]!;
      t = (((t << r) | (t >>> (32 - r))) + el) | 0;
      al = el;
      el = dl;
      dl = (cl << 10) | (cl >>> 22);
      cl = bl;
      bl = t;
      t = (ar + (br ^ cr ^ dr) + x[RR[i]!]!) | 0;
      r = SR[i]!;
      t = (((t << r) | (t >>> (32 - r))) + er) | 0;
      ar = er;
      er = dr;
      dr = (cr << 10) | (cr >>> 22);
      cr = br;
      br = t;
    }
    t = (s[1]! + cl + dr) | 0;
    s[1] = (s[2]! + dl + er) | 0;
    s[2] = (s[3]! + el + ar) | 0;
    s[3] = (s[4]! + al + br) | 0;
    s[4] = (s[0]! + bl + cr) | 0;
    s[0] = t;
  }
}

/**
 * RIPEMD-160 of the input.
 *
 * @param data - Bytes to hash.
 * @returns {Uint8Array} 20 bytes.
 */
export function ripemd160(data: Uint8Array): Uint8Array {
  return new Ripemd160Hasher().update(data).digest();
}

/**
 * RIPEMD-160 of SHA-256, the hash behind Bitcoin's public key and script addresses.
 *
 * @param data - Bytes to hash, usually a public key or a script.
 * @returns {Uint8Array} 20 bytes.
 */
export function hash160(data: Uint8Array): Uint8Array {
  return ripemd160(sha256(data));
}
