/**
 * SHA-256, SHA-384 and SHA-512 (FIPS 180-4). SHA-512 keeps each 64-bit word as a high and a low
 * 32-bit half. A sum adds its low halves as unsigned numbers, exact below 2^53, and carries the
 * part above 2^32 into the high half. Summing up to five terms at once ran about 30% faster in an
 * interleaved run than a branchless int32 carry after each addition, the way BLAKE2b adds two.
 */
import { InvalidOptionError } from "./errors.ts";
import { MerkleDamgard, assertBytes } from "./hasher.ts";

/** SHA-256 round constants. */
const K256 = new Int32Array([
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
]);

/** SHA-256 initial value, which BLAKE2s shares. */
export const IV256 = new Int32Array([
  0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
]);

/** Message schedule scratch, shared: hashing is synchronous. */
const W256 = new Int32Array(64);

/** SHA-256. */
export class Sha256Hasher extends MerkleDamgard {
  protected readonly state = IV256.slice();

  constructor() {
    super(64, 32, false);
  }

  protected compress(view: DataView, offset: number): void {
    const s = this.state;
    const w = W256;
    for (let i = 0; i < 16; i++) w[i] = view.getInt32(offset + i * 4);
    for (let i = 16; i < 64; i++) {
      const x = w[i - 15]!;
      const y = w[i - 2]!;
      const s0 = ((x >>> 7) | (x << 25)) ^ ((x >>> 18) | (x << 14)) ^ (x >>> 3);
      const s1 = ((y >>> 17) | (y << 15)) ^ ((y >>> 19) | (y << 13)) ^ (y >>> 10);
      w[i] = (s1 + w[i - 7]! + s0 + w[i - 16]!) | 0;
    }
    let a = s[0]!;
    let b = s[1]!;
    let c = s[2]!;
    let d = s[3]!;
    let e = s[4]!;
    let f = s[5]!;
    let g = s[6]!;
    let h = s[7]!;
    for (let i = 0; i < 64; i++) {
      const sigma1 = ((e >>> 6) | (e << 26)) ^ ((e >>> 11) | (e << 21)) ^ ((e >>> 25) | (e << 7));
      const t1 = (h + sigma1 + ((e & f) ^ (~e & g)) + K256[i]! + w[i]!) | 0;
      const sigma0 = ((a >>> 2) | (a << 30)) ^ ((a >>> 13) | (a << 19)) ^ ((a >>> 22) | (a << 10));
      const t2 = (sigma0 + ((a & b) ^ (a & c) ^ (b & c))) | 0;
      h = g;
      g = f;
      f = e;
      e = (d + t1) | 0;
      d = c;
      c = b;
      b = a;
      a = (t1 + t2) | 0;
    }
    s[0] = (s[0]! + a) | 0;
    s[1] = (s[1]! + b) | 0;
    s[2] = (s[2]! + c) | 0;
    s[3] = (s[3]! + d) | 0;
    s[4] = (s[4]! + e) | 0;
    s[5] = (s[5]! + f) | 0;
    s[6] = (s[6]! + g) | 0;
    s[7] = (s[7]! + h) | 0;
  }
}

/** SHA-512 round constants, high then low half. */
const K512 = new Int32Array([
  0x428a2f98, 0xd728ae22, 0x71374491, 0x23ef65cd, 0xb5c0fbcf, 0xec4d3b2f, 0xe9b5dba5, 0x8189dbbc,
  0x3956c25b, 0xf348b538, 0x59f111f1, 0xb605d019, 0x923f82a4, 0xaf194f9b, 0xab1c5ed5, 0xda6d8118,
  0xd807aa98, 0xa3030242, 0x12835b01, 0x45706fbe, 0x243185be, 0x4ee4b28c, 0x550c7dc3, 0xd5ffb4e2,
  0x72be5d74, 0xf27b896f, 0x80deb1fe, 0x3b1696b1, 0x9bdc06a7, 0x25c71235, 0xc19bf174, 0xcf692694,
  0xe49b69c1, 0x9ef14ad2, 0xefbe4786, 0x384f25e3, 0x0fc19dc6, 0x8b8cd5b5, 0x240ca1cc, 0x77ac9c65,
  0x2de92c6f, 0x592b0275, 0x4a7484aa, 0x6ea6e483, 0x5cb0a9dc, 0xbd41fbd4, 0x76f988da, 0x831153b5,
  0x983e5152, 0xee66dfab, 0xa831c66d, 0x2db43210, 0xb00327c8, 0x98fb213f, 0xbf597fc7, 0xbeef0ee4,
  0xc6e00bf3, 0x3da88fc2, 0xd5a79147, 0x930aa725, 0x06ca6351, 0xe003826f, 0x14292967, 0x0a0e6e70,
  0x27b70a85, 0x46d22ffc, 0x2e1b2138, 0x5c26c926, 0x4d2c6dfc, 0x5ac42aed, 0x53380d13, 0x9d95b3df,
  0x650a7354, 0x8baf63de, 0x766a0abb, 0x3c77b2a8, 0x81c2c92e, 0x47edaee6, 0x92722c85, 0x1482353b,
  0xa2bfe8a1, 0x4cf10364, 0xa81a664b, 0xbc423001, 0xc24b8b70, 0xd0f89791, 0xc76c51a3, 0x0654be30,
  0xd192e819, 0xd6ef5218, 0xd6990624, 0x5565a910, 0xf40e3585, 0x5771202a, 0x106aa070, 0x32bbd1b8,
  0x19a4c116, 0xb8d2d0c8, 0x1e376c08, 0x5141ab53, 0x2748774c, 0xdf8eeb99, 0x34b0bcb5, 0xe19b48a8,
  0x391c0cb3, 0xc5c95a63, 0x4ed8aa4a, 0xe3418acb, 0x5b9cca4f, 0x7763e373, 0x682e6ff3, 0xd6b2b8a3,
  0x748f82ee, 0x5defb2fc, 0x78a5636f, 0x43172f60, 0x84c87814, 0xa1f0ab72, 0x8cc70208, 0x1a6439ec,
  0x90befffa, 0x23631e28, 0xa4506ceb, 0xde82bde9, 0xbef9a3f7, 0xb2c67915, 0xc67178f2, 0xe372532b,
  0xca273ece, 0xea26619c, 0xd186b8c7, 0x21c0c207, 0xeada7dd6, 0xcde0eb1e, 0xf57d4f7f, 0xee6ed178,
  0x06f067aa, 0x72176fba, 0x0a637dc5, 0xa2c898a6, 0x113f9804, 0xbef90dae, 0x1b710b35, 0x131c471b,
  0x28db77f5, 0x23047d84, 0x32caab7b, 0x40c72493, 0x3c9ebe0a, 0x15c9bebc, 0x431d67c4, 0x9c100d4c,
  0x4cc5d4be, 0xcb3e42b6, 0x597f299c, 0xfc657e2a, 0x5fcb6fab, 0x3ad6faec, 0x6c44198c, 0x4a475817,
]);

/** SHA-512 initial value. */
const IV512 = new Int32Array([
  0x6a09e667, 0xf3bcc908, 0xbb67ae85, 0x84caa73b, 0x3c6ef372, 0xfe94f82b, 0xa54ff53a, 0x5f1d36f1,
  0x510e527f, 0xade682d1, 0x9b05688c, 0x2b3e6c1f, 0x1f83d9ab, 0xfb41bd6b, 0x5be0cd19, 0x137e2179,
]);

/** SHA-384 initial value. */
const IV384 = new Int32Array([
  0xcbbb9d5d, 0xc1059ed8, 0x629a292a, 0x367cd507, 0x9159015a, 0x3070dd17, 0x152fecd8, 0xf70e5939,
  0x67332667, 0xffc00b31, 0x8eb44a87, 0x68581511, 0xdb0c2e0d, 0x64f98fa7, 0x47b5481d, 0xbefa4fa4,
]);

/** Message schedule scratch as high and low halves. */
const W512 = new Int32Array(160);

/** SHA-512, or SHA-384 with a 48-byte output. */
export class Sha512Hasher extends MerkleDamgard {
  protected readonly state: Int32Array;

  /**
   * @param outputLength - 64 for SHA-512, 48 for SHA-384.
   */
  constructor(outputLength: 48 | 64 = 64) {
    // Any other length would truncate SHA-512 under its own IV, which is no standard hash.
    if (outputLength !== 48 && outputLength !== 64) {
      throw new InvalidOptionError("outputLength", outputLength, "must be 48 or 64");
    }
    super(128, outputLength, false);
    this.state = (outputLength === 48 ? IV384 : IV512).slice();
  }

  protected compress(view: DataView, offset: number): void {
    const s = this.state;
    const w = W512;
    for (let i = 0; i < 32; i++) w[i] = view.getInt32(offset + i * 4);
    for (let i = 32; i < 160; i += 2) {
      // sigma0 of w[t-15]: rotate 1, rotate 8, shift 7.
      let xh = w[i - 30]!;
      let xl = w[i - 29]!;
      const sh = ((xh >>> 1) | (xl << 31)) ^ ((xh >>> 8) | (xl << 24)) ^ (xh >>> 7);
      const sl = ((xl >>> 1) | (xh << 31)) ^ ((xl >>> 8) | (xh << 24)) ^ ((xl >>> 7) | (xh << 25));
      // sigma1 of w[t-2]: rotate 19, rotate 61, shift 6.
      xh = w[i - 4]!;
      xl = w[i - 3]!;
      const rh = ((xh >>> 19) | (xl << 13)) ^ ((xl >>> 29) | (xh << 3)) ^ (xh >>> 6);
      const rl = ((xl >>> 19) | (xh << 13)) ^ ((xh >>> 29) | (xl << 3)) ^ ((xl >>> 6) | (xh << 26));
      const low = (sl >>> 0) + (rl >>> 0) + (w[i - 13]! >>> 0) + (w[i - 31]! >>> 0);
      w[i] = (sh + rh + w[i - 14]! + w[i - 32]! + ((low / 0x1_0000_0000) | 0)) | 0;
      w[i + 1] = low | 0;
    }
    let ah = s[0]!;
    let al = s[1]!;
    let bh = s[2]!;
    let bl = s[3]!;
    let ch = s[4]!;
    let cl = s[5]!;
    let dh = s[6]!;
    let dl = s[7]!;
    let eh = s[8]!;
    let el = s[9]!;
    let fh = s[10]!;
    let fl = s[11]!;
    let gh = s[12]!;
    let gl = s[13]!;
    let hh = s[14]!;
    let hl = s[15]!;
    for (let i = 0; i < 160; i += 2) {
      // t1 = h + Sigma1(e) + Ch(e, f, g) + K + W, Sigma1: rotate 14, 18, 41. The low halves are
      // summed as unsigned values below 2^35, whose top bits are the carry.
      const sh =
        ((eh >>> 14) | (el << 18)) ^ ((eh >>> 18) | (el << 14)) ^ ((el >>> 9) | (eh << 23));
      const sl =
        ((el >>> 14) | (eh << 18)) ^ ((el >>> 18) | (eh << 14)) ^ ((eh >>> 9) | (el << 23));
      const chh = (eh & fh) ^ (~eh & gh);
      const chl = (el & fl) ^ (~el & gl);
      const t1l = (hl >>> 0) + (sl >>> 0) + (chl >>> 0) + (K512[i + 1]! >>> 0) + (w[i + 1]! >>> 0);
      const t1h = (hh + sh + chh + K512[i]! + w[i]! + ((t1l / 0x1_0000_0000) | 0)) | 0;
      // t2 = Sigma0(a) + Maj(a, b, c), Sigma0: rotate 28, 34, 39.
      const uh = ((ah >>> 28) | (al << 4)) ^ ((al >>> 2) | (ah << 30)) ^ ((al >>> 7) | (ah << 25));
      const ul = ((al >>> 28) | (ah << 4)) ^ ((ah >>> 2) | (al << 30)) ^ ((ah >>> 7) | (al << 25));
      const mh = (ah & bh) ^ (ah & ch) ^ (bh & ch);
      const ml = (al & bl) ^ (al & cl) ^ (bl & cl);
      hh = gh;
      hl = gl;
      gh = fh;
      gl = fl;
      fh = eh;
      fl = el;
      let x = (dl >>> 0) + (t1l >>> 0);
      eh = (dh + t1h + ((x / 0x1_0000_0000) | 0)) | 0;
      el = x | 0;
      dh = ch;
      dl = cl;
      ch = bh;
      cl = bl;
      bh = ah;
      bl = al;
      x = (t1l >>> 0) + (ul >>> 0) + (ml >>> 0);
      ah = (t1h + uh + mh + ((x / 0x1_0000_0000) | 0)) | 0;
      al = x | 0;
    }
    add(s, 0, ah, al);
    add(s, 2, bh, bl);
    add(s, 4, ch, cl);
    add(s, 6, dh, dl);
    add(s, 8, eh, el);
    add(s, 10, fh, fl);
    add(s, 12, gh, gl);
    add(s, 14, hh, hl);
  }
}

/**
 * Adds a 64-bit word into the state.
 *
 * @param s - The state, high then low halves.
 * @param i - Index of the high half.
 * @param high - High half to add.
 * @param low - Low half to add.
 */
function add(s: Int32Array, i: number, high: number, low: number): void {
  const l = s[i + 1]!;
  const t = (l + low) | 0;
  s[i] = (s[i]! + high + (((l & low) | ((l | low) & ~t)) >>> 31)) | 0;
  s[i + 1] = t;
}

/**
 * SHA-256 of the input.
 *
 * @param data - Bytes to hash.
 * @returns {Uint8Array} 32 bytes.
 */
export function sha256(data: Uint8Array): Uint8Array {
  assertBytes(data, "data");
  return new Sha256Hasher().update(data).digest();
}

/**
 * SHA-512 of the input.
 *
 * @param data - Bytes to hash.
 * @returns {Uint8Array} 64 bytes.
 */
export function sha512(data: Uint8Array): Uint8Array {
  assertBytes(data, "data");
  return new Sha512Hasher().update(data).digest();
}

/**
 * SHA-256 of SHA-256, which Bitcoin hashes blocks, transactions and checksums with.
 *
 * @param data - Bytes to hash.
 * @returns {Uint8Array} 32 bytes.
 */
export function hash256(data: Uint8Array): Uint8Array {
  return sha256(sha256(data));
}
