/** scrypt (RFC 7914): PBKDF2-HMAC-SHA256 around ROMix, whose BlockMix runs Salsa20/8. */
import { pbkdf2 } from "./hmac.ts";
import { Sha256Hasher } from "./sha2.ts";

/**
 * Runs Salsa20/8 on the sixteen words at `x[0..16]`, adding the input back in.
 *
 * @param x - The words, updated in place.
 */
function salsa20_8(x: Int32Array): void {
  const j0 = x[0]!;
  const j1 = x[1]!;
  const j2 = x[2]!;
  const j3 = x[3]!;
  const j4 = x[4]!;
  const j5 = x[5]!;
  const j6 = x[6]!;
  const j7 = x[7]!;
  const j8 = x[8]!;
  const j9 = x[9]!;
  const j10 = x[10]!;
  const j11 = x[11]!;
  const j12 = x[12]!;
  const j13 = x[13]!;
  const j14 = x[14]!;
  const j15 = x[15]!;
  let x0 = j0;
  let x1 = j1;
  let x2 = j2;
  let x3 = j3;
  let x4 = j4;
  let x5 = j5;
  let x6 = j6;
  let x7 = j7;
  let x8 = j8;
  let x9 = j9;
  let x10 = j10;
  let x11 = j11;
  let x12 = j12;
  let x13 = j13;
  let x14 = j14;
  let x15 = j15;
  let t = 0;
  for (let i = 0; i < 8; i += 2) {
    // Columns.
    t = (x0 + x12) | 0;
    x4 ^= (t << 7) | (t >>> 25);
    t = (x4 + x0) | 0;
    x8 ^= (t << 9) | (t >>> 23);
    t = (x8 + x4) | 0;
    x12 ^= (t << 13) | (t >>> 19);
    t = (x12 + x8) | 0;
    x0 ^= (t << 18) | (t >>> 14);
    t = (x5 + x1) | 0;
    x9 ^= (t << 7) | (t >>> 25);
    t = (x9 + x5) | 0;
    x13 ^= (t << 9) | (t >>> 23);
    t = (x13 + x9) | 0;
    x1 ^= (t << 13) | (t >>> 19);
    t = (x1 + x13) | 0;
    x5 ^= (t << 18) | (t >>> 14);
    t = (x10 + x6) | 0;
    x14 ^= (t << 7) | (t >>> 25);
    t = (x14 + x10) | 0;
    x2 ^= (t << 9) | (t >>> 23);
    t = (x2 + x14) | 0;
    x6 ^= (t << 13) | (t >>> 19);
    t = (x6 + x2) | 0;
    x10 ^= (t << 18) | (t >>> 14);
    t = (x15 + x11) | 0;
    x3 ^= (t << 7) | (t >>> 25);
    t = (x3 + x15) | 0;
    x7 ^= (t << 9) | (t >>> 23);
    t = (x7 + x3) | 0;
    x11 ^= (t << 13) | (t >>> 19);
    t = (x11 + x7) | 0;
    x15 ^= (t << 18) | (t >>> 14);
    // Rows.
    t = (x0 + x3) | 0;
    x1 ^= (t << 7) | (t >>> 25);
    t = (x1 + x0) | 0;
    x2 ^= (t << 9) | (t >>> 23);
    t = (x2 + x1) | 0;
    x3 ^= (t << 13) | (t >>> 19);
    t = (x3 + x2) | 0;
    x0 ^= (t << 18) | (t >>> 14);
    t = (x5 + x4) | 0;
    x6 ^= (t << 7) | (t >>> 25);
    t = (x6 + x5) | 0;
    x7 ^= (t << 9) | (t >>> 23);
    t = (x7 + x6) | 0;
    x4 ^= (t << 13) | (t >>> 19);
    t = (x4 + x7) | 0;
    x5 ^= (t << 18) | (t >>> 14);
    t = (x10 + x9) | 0;
    x11 ^= (t << 7) | (t >>> 25);
    t = (x11 + x10) | 0;
    x8 ^= (t << 9) | (t >>> 23);
    t = (x8 + x11) | 0;
    x9 ^= (t << 13) | (t >>> 19);
    t = (x9 + x8) | 0;
    x10 ^= (t << 18) | (t >>> 14);
    t = (x15 + x14) | 0;
    x12 ^= (t << 7) | (t >>> 25);
    t = (x12 + x15) | 0;
    x13 ^= (t << 9) | (t >>> 23);
    t = (x13 + x12) | 0;
    x14 ^= (t << 13) | (t >>> 19);
    t = (x14 + x13) | 0;
    x15 ^= (t << 18) | (t >>> 14);
  }
  x[0] = (x0 + j0) | 0;
  x[1] = (x1 + j1) | 0;
  x[2] = (x2 + j2) | 0;
  x[3] = (x3 + j3) | 0;
  x[4] = (x4 + j4) | 0;
  x[5] = (x5 + j5) | 0;
  x[6] = (x6 + j6) | 0;
  x[7] = (x7 + j7) | 0;
  x[8] = (x8 + j8) | 0;
  x[9] = (x9 + j9) | 0;
  x[10] = (x10 + j10) | 0;
  x[11] = (x11 + j11) | 0;
  x[12] = (x12 + j12) | 0;
  x[13] = (x13 + j13) | 0;
  x[14] = (x14 + j14) | 0;
  x[15] = (x15 + j15) | 0;
}

/**
 * BlockMix: runs Salsa20/8 along the 2r blocks of sixteen words in `input`, writing the even
 * outputs to the first half of `output` and the odd ones to the second.
 *
 * @param input - 32r words.
 * @param output - 32r words, not the same array as `input`.
 * @param x - Sixteen words of scratch.
 * @param r - Block size.
 */
function blockMix(input: Int32Array, output: Int32Array, x: Int32Array, r: number): void {
  x.set(input.subarray(32 * r - 16, 32 * r));
  for (let i = 0; i < 2 * r; i++) {
    for (let k = 0; k < 16; k++) x[k] = x[k]! ^ input[i * 16 + k]!;
    salsa20_8(x);
    output.set(x, (i >> 1) * 16 + (i & 1) * 16 * r);
  }
}

/**
 * Derives a key with scrypt.
 *
 * @param password - The password.
 * @param salt - The salt.
 * @param N - CPU and memory cost, a power of 2.
 * @param r - Block size.
 * @param p - Parallelization.
 * @param keyLength - Output bytes.
 * @returns {Uint8Array} The derived key.
 */
export function scrypt(
  password: Uint8Array,
  salt: Uint8Array,
  N: number,
  r: number,
  p: number,
  keyLength: number,
): Uint8Array {
  const words = 32 * r;
  const b = pbkdf2(new Sha256Hasher(), password, salt, 1, p * 128 * r);
  const view = new DataView(b.buffer);
  const v = new Int32Array(words * N);
  let x = new Int32Array(words);
  let y = new Int32Array(words);
  const scratch = new Int32Array(16);
  for (let block = 0; block < p; block++) {
    const base = block * 128 * r;
    for (let i = 0; i < words; i++) x[i] = view.getInt32(base + i * 4, true);
    for (let i = 0; i < N; i++) {
      v.set(x, i * words);
      blockMix(x, y, scratch, r);
      [x, y] = [y, x];
    }
    for (let i = 0; i < N; i++) {
      // Integerify: the first word of the last sixteen, whose low bits pick a block below N.
      const j = x[words - 16]! & (N - 1);
      for (let k = 0, o = j * words; k < words; k++) x[k] = x[k]! ^ v[o + k]!;
      blockMix(x, y, scratch, r);
      [x, y] = [y, x];
    }
    for (let i = 0; i < words; i++) view.setInt32(base + i * 4, x[i]!, true);
  }
  return pbkdf2(new Sha256Hasher(), password, b, 1, keyLength);
}
