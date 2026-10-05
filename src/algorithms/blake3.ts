/**
 * BLAKE3 in plain TypeScript, after the specification by O'Connor, Aumasson, Neves and
 * Wilcox-O'Hearn. Only the default hash mode with a 32-byte output: no keyed or derive-key mode.
 */
import { FixedHash } from "../core/fixed-hash.ts";

const CHUNK_LEN = 1024;
const BLOCK_LEN = 64;
const CHUNK_START = 1;
const CHUNK_END = 2;
const PARENT = 4;
const ROOT = 8;

/** The SHA-256 initial hash values, which BLAKE3 uses as its key in hash mode. */
const IV = /* @__PURE__ */ new Uint32Array([
  0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
]);

/**
 * Runs the compression function and writes the first eight output words, the chaining value.
 * The seven rounds are unrolled with the message schedule already permuted, so the hot loop
 * touches only local variables.
 *
 * @param cv - Input chaining value, eight words.
 * @param m - Message block, sixteen little-endian words.
 * @param counter - Chunk counter; only its low 32 bits, since the input fits in memory.
 * @param blockLength - Bytes of the block that carry data.
 * @param flags - Domain flags.
 * @param out - Where the eight output words go; may be `cv` itself.
 */
function compress(
  cv: Uint32Array,
  m: Uint32Array,
  counter: number,
  blockLength: number,
  flags: number,
  out: Uint32Array,
): void {
  const m0 = m[0]!;
  const m1 = m[1]!;
  const m2 = m[2]!;
  const m3 = m[3]!;
  const m4 = m[4]!;
  const m5 = m[5]!;
  const m6 = m[6]!;
  const m7 = m[7]!;
  const m8 = m[8]!;
  const m9 = m[9]!;
  const m10 = m[10]!;
  const m11 = m[11]!;
  const m12 = m[12]!;
  const m13 = m[13]!;
  const m14 = m[14]!;
  const m15 = m[15]!;
  let s0 = cv[0]! | 0;
  let s1 = cv[1]! | 0;
  let s2 = cv[2]! | 0;
  let s3 = cv[3]! | 0;
  let s4 = cv[4]! | 0;
  let s5 = cv[5]! | 0;
  let s6 = cv[6]! | 0;
  let s7 = cv[7]! | 0;
  let s8 = IV[0]! | 0;
  let s9 = IV[1]! | 0;
  let s10 = IV[2]! | 0;
  let s11 = IV[3]! | 0;
  let s12 = counter | 0;
  let s13 = Math.floor(counter / 0x1_0000_0000) | 0;
  let s14 = blockLength | 0;
  let s15 = flags | 0;
  // Round 1
  s0 = (s0 + s4 + m0) | 0;
  s12 ^= s0;
  s12 = (s12 >>> 16) | (s12 << 16);
  s8 = (s8 + s12) | 0;
  s4 ^= s8;
  s4 = (s4 >>> 12) | (s4 << 20);
  s0 = (s0 + s4 + m1) | 0;
  s12 ^= s0;
  s12 = (s12 >>> 8) | (s12 << 24);
  s8 = (s8 + s12) | 0;
  s4 ^= s8;
  s4 = (s4 >>> 7) | (s4 << 25);
  s1 = (s1 + s5 + m2) | 0;
  s13 ^= s1;
  s13 = (s13 >>> 16) | (s13 << 16);
  s9 = (s9 + s13) | 0;
  s5 ^= s9;
  s5 = (s5 >>> 12) | (s5 << 20);
  s1 = (s1 + s5 + m3) | 0;
  s13 ^= s1;
  s13 = (s13 >>> 8) | (s13 << 24);
  s9 = (s9 + s13) | 0;
  s5 ^= s9;
  s5 = (s5 >>> 7) | (s5 << 25);
  s2 = (s2 + s6 + m4) | 0;
  s14 ^= s2;
  s14 = (s14 >>> 16) | (s14 << 16);
  s10 = (s10 + s14) | 0;
  s6 ^= s10;
  s6 = (s6 >>> 12) | (s6 << 20);
  s2 = (s2 + s6 + m5) | 0;
  s14 ^= s2;
  s14 = (s14 >>> 8) | (s14 << 24);
  s10 = (s10 + s14) | 0;
  s6 ^= s10;
  s6 = (s6 >>> 7) | (s6 << 25);
  s3 = (s3 + s7 + m6) | 0;
  s15 ^= s3;
  s15 = (s15 >>> 16) | (s15 << 16);
  s11 = (s11 + s15) | 0;
  s7 ^= s11;
  s7 = (s7 >>> 12) | (s7 << 20);
  s3 = (s3 + s7 + m7) | 0;
  s15 ^= s3;
  s15 = (s15 >>> 8) | (s15 << 24);
  s11 = (s11 + s15) | 0;
  s7 ^= s11;
  s7 = (s7 >>> 7) | (s7 << 25);
  s0 = (s0 + s5 + m8) | 0;
  s15 ^= s0;
  s15 = (s15 >>> 16) | (s15 << 16);
  s10 = (s10 + s15) | 0;
  s5 ^= s10;
  s5 = (s5 >>> 12) | (s5 << 20);
  s0 = (s0 + s5 + m9) | 0;
  s15 ^= s0;
  s15 = (s15 >>> 8) | (s15 << 24);
  s10 = (s10 + s15) | 0;
  s5 ^= s10;
  s5 = (s5 >>> 7) | (s5 << 25);
  s1 = (s1 + s6 + m10) | 0;
  s12 ^= s1;
  s12 = (s12 >>> 16) | (s12 << 16);
  s11 = (s11 + s12) | 0;
  s6 ^= s11;
  s6 = (s6 >>> 12) | (s6 << 20);
  s1 = (s1 + s6 + m11) | 0;
  s12 ^= s1;
  s12 = (s12 >>> 8) | (s12 << 24);
  s11 = (s11 + s12) | 0;
  s6 ^= s11;
  s6 = (s6 >>> 7) | (s6 << 25);
  s2 = (s2 + s7 + m12) | 0;
  s13 ^= s2;
  s13 = (s13 >>> 16) | (s13 << 16);
  s8 = (s8 + s13) | 0;
  s7 ^= s8;
  s7 = (s7 >>> 12) | (s7 << 20);
  s2 = (s2 + s7 + m13) | 0;
  s13 ^= s2;
  s13 = (s13 >>> 8) | (s13 << 24);
  s8 = (s8 + s13) | 0;
  s7 ^= s8;
  s7 = (s7 >>> 7) | (s7 << 25);
  s3 = (s3 + s4 + m14) | 0;
  s14 ^= s3;
  s14 = (s14 >>> 16) | (s14 << 16);
  s9 = (s9 + s14) | 0;
  s4 ^= s9;
  s4 = (s4 >>> 12) | (s4 << 20);
  s3 = (s3 + s4 + m15) | 0;
  s14 ^= s3;
  s14 = (s14 >>> 8) | (s14 << 24);
  s9 = (s9 + s14) | 0;
  s4 ^= s9;
  s4 = (s4 >>> 7) | (s4 << 25);
  // Round 2
  s0 = (s0 + s4 + m2) | 0;
  s12 ^= s0;
  s12 = (s12 >>> 16) | (s12 << 16);
  s8 = (s8 + s12) | 0;
  s4 ^= s8;
  s4 = (s4 >>> 12) | (s4 << 20);
  s0 = (s0 + s4 + m6) | 0;
  s12 ^= s0;
  s12 = (s12 >>> 8) | (s12 << 24);
  s8 = (s8 + s12) | 0;
  s4 ^= s8;
  s4 = (s4 >>> 7) | (s4 << 25);
  s1 = (s1 + s5 + m3) | 0;
  s13 ^= s1;
  s13 = (s13 >>> 16) | (s13 << 16);
  s9 = (s9 + s13) | 0;
  s5 ^= s9;
  s5 = (s5 >>> 12) | (s5 << 20);
  s1 = (s1 + s5 + m10) | 0;
  s13 ^= s1;
  s13 = (s13 >>> 8) | (s13 << 24);
  s9 = (s9 + s13) | 0;
  s5 ^= s9;
  s5 = (s5 >>> 7) | (s5 << 25);
  s2 = (s2 + s6 + m7) | 0;
  s14 ^= s2;
  s14 = (s14 >>> 16) | (s14 << 16);
  s10 = (s10 + s14) | 0;
  s6 ^= s10;
  s6 = (s6 >>> 12) | (s6 << 20);
  s2 = (s2 + s6 + m0) | 0;
  s14 ^= s2;
  s14 = (s14 >>> 8) | (s14 << 24);
  s10 = (s10 + s14) | 0;
  s6 ^= s10;
  s6 = (s6 >>> 7) | (s6 << 25);
  s3 = (s3 + s7 + m4) | 0;
  s15 ^= s3;
  s15 = (s15 >>> 16) | (s15 << 16);
  s11 = (s11 + s15) | 0;
  s7 ^= s11;
  s7 = (s7 >>> 12) | (s7 << 20);
  s3 = (s3 + s7 + m13) | 0;
  s15 ^= s3;
  s15 = (s15 >>> 8) | (s15 << 24);
  s11 = (s11 + s15) | 0;
  s7 ^= s11;
  s7 = (s7 >>> 7) | (s7 << 25);
  s0 = (s0 + s5 + m1) | 0;
  s15 ^= s0;
  s15 = (s15 >>> 16) | (s15 << 16);
  s10 = (s10 + s15) | 0;
  s5 ^= s10;
  s5 = (s5 >>> 12) | (s5 << 20);
  s0 = (s0 + s5 + m11) | 0;
  s15 ^= s0;
  s15 = (s15 >>> 8) | (s15 << 24);
  s10 = (s10 + s15) | 0;
  s5 ^= s10;
  s5 = (s5 >>> 7) | (s5 << 25);
  s1 = (s1 + s6 + m12) | 0;
  s12 ^= s1;
  s12 = (s12 >>> 16) | (s12 << 16);
  s11 = (s11 + s12) | 0;
  s6 ^= s11;
  s6 = (s6 >>> 12) | (s6 << 20);
  s1 = (s1 + s6 + m5) | 0;
  s12 ^= s1;
  s12 = (s12 >>> 8) | (s12 << 24);
  s11 = (s11 + s12) | 0;
  s6 ^= s11;
  s6 = (s6 >>> 7) | (s6 << 25);
  s2 = (s2 + s7 + m9) | 0;
  s13 ^= s2;
  s13 = (s13 >>> 16) | (s13 << 16);
  s8 = (s8 + s13) | 0;
  s7 ^= s8;
  s7 = (s7 >>> 12) | (s7 << 20);
  s2 = (s2 + s7 + m14) | 0;
  s13 ^= s2;
  s13 = (s13 >>> 8) | (s13 << 24);
  s8 = (s8 + s13) | 0;
  s7 ^= s8;
  s7 = (s7 >>> 7) | (s7 << 25);
  s3 = (s3 + s4 + m15) | 0;
  s14 ^= s3;
  s14 = (s14 >>> 16) | (s14 << 16);
  s9 = (s9 + s14) | 0;
  s4 ^= s9;
  s4 = (s4 >>> 12) | (s4 << 20);
  s3 = (s3 + s4 + m8) | 0;
  s14 ^= s3;
  s14 = (s14 >>> 8) | (s14 << 24);
  s9 = (s9 + s14) | 0;
  s4 ^= s9;
  s4 = (s4 >>> 7) | (s4 << 25);
  // Round 3
  s0 = (s0 + s4 + m3) | 0;
  s12 ^= s0;
  s12 = (s12 >>> 16) | (s12 << 16);
  s8 = (s8 + s12) | 0;
  s4 ^= s8;
  s4 = (s4 >>> 12) | (s4 << 20);
  s0 = (s0 + s4 + m4) | 0;
  s12 ^= s0;
  s12 = (s12 >>> 8) | (s12 << 24);
  s8 = (s8 + s12) | 0;
  s4 ^= s8;
  s4 = (s4 >>> 7) | (s4 << 25);
  s1 = (s1 + s5 + m10) | 0;
  s13 ^= s1;
  s13 = (s13 >>> 16) | (s13 << 16);
  s9 = (s9 + s13) | 0;
  s5 ^= s9;
  s5 = (s5 >>> 12) | (s5 << 20);
  s1 = (s1 + s5 + m12) | 0;
  s13 ^= s1;
  s13 = (s13 >>> 8) | (s13 << 24);
  s9 = (s9 + s13) | 0;
  s5 ^= s9;
  s5 = (s5 >>> 7) | (s5 << 25);
  s2 = (s2 + s6 + m13) | 0;
  s14 ^= s2;
  s14 = (s14 >>> 16) | (s14 << 16);
  s10 = (s10 + s14) | 0;
  s6 ^= s10;
  s6 = (s6 >>> 12) | (s6 << 20);
  s2 = (s2 + s6 + m2) | 0;
  s14 ^= s2;
  s14 = (s14 >>> 8) | (s14 << 24);
  s10 = (s10 + s14) | 0;
  s6 ^= s10;
  s6 = (s6 >>> 7) | (s6 << 25);
  s3 = (s3 + s7 + m7) | 0;
  s15 ^= s3;
  s15 = (s15 >>> 16) | (s15 << 16);
  s11 = (s11 + s15) | 0;
  s7 ^= s11;
  s7 = (s7 >>> 12) | (s7 << 20);
  s3 = (s3 + s7 + m14) | 0;
  s15 ^= s3;
  s15 = (s15 >>> 8) | (s15 << 24);
  s11 = (s11 + s15) | 0;
  s7 ^= s11;
  s7 = (s7 >>> 7) | (s7 << 25);
  s0 = (s0 + s5 + m6) | 0;
  s15 ^= s0;
  s15 = (s15 >>> 16) | (s15 << 16);
  s10 = (s10 + s15) | 0;
  s5 ^= s10;
  s5 = (s5 >>> 12) | (s5 << 20);
  s0 = (s0 + s5 + m5) | 0;
  s15 ^= s0;
  s15 = (s15 >>> 8) | (s15 << 24);
  s10 = (s10 + s15) | 0;
  s5 ^= s10;
  s5 = (s5 >>> 7) | (s5 << 25);
  s1 = (s1 + s6 + m9) | 0;
  s12 ^= s1;
  s12 = (s12 >>> 16) | (s12 << 16);
  s11 = (s11 + s12) | 0;
  s6 ^= s11;
  s6 = (s6 >>> 12) | (s6 << 20);
  s1 = (s1 + s6 + m0) | 0;
  s12 ^= s1;
  s12 = (s12 >>> 8) | (s12 << 24);
  s11 = (s11 + s12) | 0;
  s6 ^= s11;
  s6 = (s6 >>> 7) | (s6 << 25);
  s2 = (s2 + s7 + m11) | 0;
  s13 ^= s2;
  s13 = (s13 >>> 16) | (s13 << 16);
  s8 = (s8 + s13) | 0;
  s7 ^= s8;
  s7 = (s7 >>> 12) | (s7 << 20);
  s2 = (s2 + s7 + m15) | 0;
  s13 ^= s2;
  s13 = (s13 >>> 8) | (s13 << 24);
  s8 = (s8 + s13) | 0;
  s7 ^= s8;
  s7 = (s7 >>> 7) | (s7 << 25);
  s3 = (s3 + s4 + m8) | 0;
  s14 ^= s3;
  s14 = (s14 >>> 16) | (s14 << 16);
  s9 = (s9 + s14) | 0;
  s4 ^= s9;
  s4 = (s4 >>> 12) | (s4 << 20);
  s3 = (s3 + s4 + m1) | 0;
  s14 ^= s3;
  s14 = (s14 >>> 8) | (s14 << 24);
  s9 = (s9 + s14) | 0;
  s4 ^= s9;
  s4 = (s4 >>> 7) | (s4 << 25);
  // Round 4
  s0 = (s0 + s4 + m10) | 0;
  s12 ^= s0;
  s12 = (s12 >>> 16) | (s12 << 16);
  s8 = (s8 + s12) | 0;
  s4 ^= s8;
  s4 = (s4 >>> 12) | (s4 << 20);
  s0 = (s0 + s4 + m7) | 0;
  s12 ^= s0;
  s12 = (s12 >>> 8) | (s12 << 24);
  s8 = (s8 + s12) | 0;
  s4 ^= s8;
  s4 = (s4 >>> 7) | (s4 << 25);
  s1 = (s1 + s5 + m12) | 0;
  s13 ^= s1;
  s13 = (s13 >>> 16) | (s13 << 16);
  s9 = (s9 + s13) | 0;
  s5 ^= s9;
  s5 = (s5 >>> 12) | (s5 << 20);
  s1 = (s1 + s5 + m9) | 0;
  s13 ^= s1;
  s13 = (s13 >>> 8) | (s13 << 24);
  s9 = (s9 + s13) | 0;
  s5 ^= s9;
  s5 = (s5 >>> 7) | (s5 << 25);
  s2 = (s2 + s6 + m14) | 0;
  s14 ^= s2;
  s14 = (s14 >>> 16) | (s14 << 16);
  s10 = (s10 + s14) | 0;
  s6 ^= s10;
  s6 = (s6 >>> 12) | (s6 << 20);
  s2 = (s2 + s6 + m3) | 0;
  s14 ^= s2;
  s14 = (s14 >>> 8) | (s14 << 24);
  s10 = (s10 + s14) | 0;
  s6 ^= s10;
  s6 = (s6 >>> 7) | (s6 << 25);
  s3 = (s3 + s7 + m13) | 0;
  s15 ^= s3;
  s15 = (s15 >>> 16) | (s15 << 16);
  s11 = (s11 + s15) | 0;
  s7 ^= s11;
  s7 = (s7 >>> 12) | (s7 << 20);
  s3 = (s3 + s7 + m15) | 0;
  s15 ^= s3;
  s15 = (s15 >>> 8) | (s15 << 24);
  s11 = (s11 + s15) | 0;
  s7 ^= s11;
  s7 = (s7 >>> 7) | (s7 << 25);
  s0 = (s0 + s5 + m4) | 0;
  s15 ^= s0;
  s15 = (s15 >>> 16) | (s15 << 16);
  s10 = (s10 + s15) | 0;
  s5 ^= s10;
  s5 = (s5 >>> 12) | (s5 << 20);
  s0 = (s0 + s5 + m0) | 0;
  s15 ^= s0;
  s15 = (s15 >>> 8) | (s15 << 24);
  s10 = (s10 + s15) | 0;
  s5 ^= s10;
  s5 = (s5 >>> 7) | (s5 << 25);
  s1 = (s1 + s6 + m11) | 0;
  s12 ^= s1;
  s12 = (s12 >>> 16) | (s12 << 16);
  s11 = (s11 + s12) | 0;
  s6 ^= s11;
  s6 = (s6 >>> 12) | (s6 << 20);
  s1 = (s1 + s6 + m2) | 0;
  s12 ^= s1;
  s12 = (s12 >>> 8) | (s12 << 24);
  s11 = (s11 + s12) | 0;
  s6 ^= s11;
  s6 = (s6 >>> 7) | (s6 << 25);
  s2 = (s2 + s7 + m5) | 0;
  s13 ^= s2;
  s13 = (s13 >>> 16) | (s13 << 16);
  s8 = (s8 + s13) | 0;
  s7 ^= s8;
  s7 = (s7 >>> 12) | (s7 << 20);
  s2 = (s2 + s7 + m8) | 0;
  s13 ^= s2;
  s13 = (s13 >>> 8) | (s13 << 24);
  s8 = (s8 + s13) | 0;
  s7 ^= s8;
  s7 = (s7 >>> 7) | (s7 << 25);
  s3 = (s3 + s4 + m1) | 0;
  s14 ^= s3;
  s14 = (s14 >>> 16) | (s14 << 16);
  s9 = (s9 + s14) | 0;
  s4 ^= s9;
  s4 = (s4 >>> 12) | (s4 << 20);
  s3 = (s3 + s4 + m6) | 0;
  s14 ^= s3;
  s14 = (s14 >>> 8) | (s14 << 24);
  s9 = (s9 + s14) | 0;
  s4 ^= s9;
  s4 = (s4 >>> 7) | (s4 << 25);
  // Round 5
  s0 = (s0 + s4 + m12) | 0;
  s12 ^= s0;
  s12 = (s12 >>> 16) | (s12 << 16);
  s8 = (s8 + s12) | 0;
  s4 ^= s8;
  s4 = (s4 >>> 12) | (s4 << 20);
  s0 = (s0 + s4 + m13) | 0;
  s12 ^= s0;
  s12 = (s12 >>> 8) | (s12 << 24);
  s8 = (s8 + s12) | 0;
  s4 ^= s8;
  s4 = (s4 >>> 7) | (s4 << 25);
  s1 = (s1 + s5 + m9) | 0;
  s13 ^= s1;
  s13 = (s13 >>> 16) | (s13 << 16);
  s9 = (s9 + s13) | 0;
  s5 ^= s9;
  s5 = (s5 >>> 12) | (s5 << 20);
  s1 = (s1 + s5 + m11) | 0;
  s13 ^= s1;
  s13 = (s13 >>> 8) | (s13 << 24);
  s9 = (s9 + s13) | 0;
  s5 ^= s9;
  s5 = (s5 >>> 7) | (s5 << 25);
  s2 = (s2 + s6 + m15) | 0;
  s14 ^= s2;
  s14 = (s14 >>> 16) | (s14 << 16);
  s10 = (s10 + s14) | 0;
  s6 ^= s10;
  s6 = (s6 >>> 12) | (s6 << 20);
  s2 = (s2 + s6 + m10) | 0;
  s14 ^= s2;
  s14 = (s14 >>> 8) | (s14 << 24);
  s10 = (s10 + s14) | 0;
  s6 ^= s10;
  s6 = (s6 >>> 7) | (s6 << 25);
  s3 = (s3 + s7 + m14) | 0;
  s15 ^= s3;
  s15 = (s15 >>> 16) | (s15 << 16);
  s11 = (s11 + s15) | 0;
  s7 ^= s11;
  s7 = (s7 >>> 12) | (s7 << 20);
  s3 = (s3 + s7 + m8) | 0;
  s15 ^= s3;
  s15 = (s15 >>> 8) | (s15 << 24);
  s11 = (s11 + s15) | 0;
  s7 ^= s11;
  s7 = (s7 >>> 7) | (s7 << 25);
  s0 = (s0 + s5 + m7) | 0;
  s15 ^= s0;
  s15 = (s15 >>> 16) | (s15 << 16);
  s10 = (s10 + s15) | 0;
  s5 ^= s10;
  s5 = (s5 >>> 12) | (s5 << 20);
  s0 = (s0 + s5 + m2) | 0;
  s15 ^= s0;
  s15 = (s15 >>> 8) | (s15 << 24);
  s10 = (s10 + s15) | 0;
  s5 ^= s10;
  s5 = (s5 >>> 7) | (s5 << 25);
  s1 = (s1 + s6 + m5) | 0;
  s12 ^= s1;
  s12 = (s12 >>> 16) | (s12 << 16);
  s11 = (s11 + s12) | 0;
  s6 ^= s11;
  s6 = (s6 >>> 12) | (s6 << 20);
  s1 = (s1 + s6 + m3) | 0;
  s12 ^= s1;
  s12 = (s12 >>> 8) | (s12 << 24);
  s11 = (s11 + s12) | 0;
  s6 ^= s11;
  s6 = (s6 >>> 7) | (s6 << 25);
  s2 = (s2 + s7 + m0) | 0;
  s13 ^= s2;
  s13 = (s13 >>> 16) | (s13 << 16);
  s8 = (s8 + s13) | 0;
  s7 ^= s8;
  s7 = (s7 >>> 12) | (s7 << 20);
  s2 = (s2 + s7 + m1) | 0;
  s13 ^= s2;
  s13 = (s13 >>> 8) | (s13 << 24);
  s8 = (s8 + s13) | 0;
  s7 ^= s8;
  s7 = (s7 >>> 7) | (s7 << 25);
  s3 = (s3 + s4 + m6) | 0;
  s14 ^= s3;
  s14 = (s14 >>> 16) | (s14 << 16);
  s9 = (s9 + s14) | 0;
  s4 ^= s9;
  s4 = (s4 >>> 12) | (s4 << 20);
  s3 = (s3 + s4 + m4) | 0;
  s14 ^= s3;
  s14 = (s14 >>> 8) | (s14 << 24);
  s9 = (s9 + s14) | 0;
  s4 ^= s9;
  s4 = (s4 >>> 7) | (s4 << 25);
  // Round 6
  s0 = (s0 + s4 + m9) | 0;
  s12 ^= s0;
  s12 = (s12 >>> 16) | (s12 << 16);
  s8 = (s8 + s12) | 0;
  s4 ^= s8;
  s4 = (s4 >>> 12) | (s4 << 20);
  s0 = (s0 + s4 + m14) | 0;
  s12 ^= s0;
  s12 = (s12 >>> 8) | (s12 << 24);
  s8 = (s8 + s12) | 0;
  s4 ^= s8;
  s4 = (s4 >>> 7) | (s4 << 25);
  s1 = (s1 + s5 + m11) | 0;
  s13 ^= s1;
  s13 = (s13 >>> 16) | (s13 << 16);
  s9 = (s9 + s13) | 0;
  s5 ^= s9;
  s5 = (s5 >>> 12) | (s5 << 20);
  s1 = (s1 + s5 + m5) | 0;
  s13 ^= s1;
  s13 = (s13 >>> 8) | (s13 << 24);
  s9 = (s9 + s13) | 0;
  s5 ^= s9;
  s5 = (s5 >>> 7) | (s5 << 25);
  s2 = (s2 + s6 + m8) | 0;
  s14 ^= s2;
  s14 = (s14 >>> 16) | (s14 << 16);
  s10 = (s10 + s14) | 0;
  s6 ^= s10;
  s6 = (s6 >>> 12) | (s6 << 20);
  s2 = (s2 + s6 + m12) | 0;
  s14 ^= s2;
  s14 = (s14 >>> 8) | (s14 << 24);
  s10 = (s10 + s14) | 0;
  s6 ^= s10;
  s6 = (s6 >>> 7) | (s6 << 25);
  s3 = (s3 + s7 + m15) | 0;
  s15 ^= s3;
  s15 = (s15 >>> 16) | (s15 << 16);
  s11 = (s11 + s15) | 0;
  s7 ^= s11;
  s7 = (s7 >>> 12) | (s7 << 20);
  s3 = (s3 + s7 + m1) | 0;
  s15 ^= s3;
  s15 = (s15 >>> 8) | (s15 << 24);
  s11 = (s11 + s15) | 0;
  s7 ^= s11;
  s7 = (s7 >>> 7) | (s7 << 25);
  s0 = (s0 + s5 + m13) | 0;
  s15 ^= s0;
  s15 = (s15 >>> 16) | (s15 << 16);
  s10 = (s10 + s15) | 0;
  s5 ^= s10;
  s5 = (s5 >>> 12) | (s5 << 20);
  s0 = (s0 + s5 + m3) | 0;
  s15 ^= s0;
  s15 = (s15 >>> 8) | (s15 << 24);
  s10 = (s10 + s15) | 0;
  s5 ^= s10;
  s5 = (s5 >>> 7) | (s5 << 25);
  s1 = (s1 + s6 + m0) | 0;
  s12 ^= s1;
  s12 = (s12 >>> 16) | (s12 << 16);
  s11 = (s11 + s12) | 0;
  s6 ^= s11;
  s6 = (s6 >>> 12) | (s6 << 20);
  s1 = (s1 + s6 + m10) | 0;
  s12 ^= s1;
  s12 = (s12 >>> 8) | (s12 << 24);
  s11 = (s11 + s12) | 0;
  s6 ^= s11;
  s6 = (s6 >>> 7) | (s6 << 25);
  s2 = (s2 + s7 + m2) | 0;
  s13 ^= s2;
  s13 = (s13 >>> 16) | (s13 << 16);
  s8 = (s8 + s13) | 0;
  s7 ^= s8;
  s7 = (s7 >>> 12) | (s7 << 20);
  s2 = (s2 + s7 + m6) | 0;
  s13 ^= s2;
  s13 = (s13 >>> 8) | (s13 << 24);
  s8 = (s8 + s13) | 0;
  s7 ^= s8;
  s7 = (s7 >>> 7) | (s7 << 25);
  s3 = (s3 + s4 + m4) | 0;
  s14 ^= s3;
  s14 = (s14 >>> 16) | (s14 << 16);
  s9 = (s9 + s14) | 0;
  s4 ^= s9;
  s4 = (s4 >>> 12) | (s4 << 20);
  s3 = (s3 + s4 + m7) | 0;
  s14 ^= s3;
  s14 = (s14 >>> 8) | (s14 << 24);
  s9 = (s9 + s14) | 0;
  s4 ^= s9;
  s4 = (s4 >>> 7) | (s4 << 25);
  // Round 7
  s0 = (s0 + s4 + m11) | 0;
  s12 ^= s0;
  s12 = (s12 >>> 16) | (s12 << 16);
  s8 = (s8 + s12) | 0;
  s4 ^= s8;
  s4 = (s4 >>> 12) | (s4 << 20);
  s0 = (s0 + s4 + m15) | 0;
  s12 ^= s0;
  s12 = (s12 >>> 8) | (s12 << 24);
  s8 = (s8 + s12) | 0;
  s4 ^= s8;
  s4 = (s4 >>> 7) | (s4 << 25);
  s1 = (s1 + s5 + m5) | 0;
  s13 ^= s1;
  s13 = (s13 >>> 16) | (s13 << 16);
  s9 = (s9 + s13) | 0;
  s5 ^= s9;
  s5 = (s5 >>> 12) | (s5 << 20);
  s1 = (s1 + s5 + m0) | 0;
  s13 ^= s1;
  s13 = (s13 >>> 8) | (s13 << 24);
  s9 = (s9 + s13) | 0;
  s5 ^= s9;
  s5 = (s5 >>> 7) | (s5 << 25);
  s2 = (s2 + s6 + m1) | 0;
  s14 ^= s2;
  s14 = (s14 >>> 16) | (s14 << 16);
  s10 = (s10 + s14) | 0;
  s6 ^= s10;
  s6 = (s6 >>> 12) | (s6 << 20);
  s2 = (s2 + s6 + m9) | 0;
  s14 ^= s2;
  s14 = (s14 >>> 8) | (s14 << 24);
  s10 = (s10 + s14) | 0;
  s6 ^= s10;
  s6 = (s6 >>> 7) | (s6 << 25);
  s3 = (s3 + s7 + m8) | 0;
  s15 ^= s3;
  s15 = (s15 >>> 16) | (s15 << 16);
  s11 = (s11 + s15) | 0;
  s7 ^= s11;
  s7 = (s7 >>> 12) | (s7 << 20);
  s3 = (s3 + s7 + m6) | 0;
  s15 ^= s3;
  s15 = (s15 >>> 8) | (s15 << 24);
  s11 = (s11 + s15) | 0;
  s7 ^= s11;
  s7 = (s7 >>> 7) | (s7 << 25);
  s0 = (s0 + s5 + m14) | 0;
  s15 ^= s0;
  s15 = (s15 >>> 16) | (s15 << 16);
  s10 = (s10 + s15) | 0;
  s5 ^= s10;
  s5 = (s5 >>> 12) | (s5 << 20);
  s0 = (s0 + s5 + m10) | 0;
  s15 ^= s0;
  s15 = (s15 >>> 8) | (s15 << 24);
  s10 = (s10 + s15) | 0;
  s5 ^= s10;
  s5 = (s5 >>> 7) | (s5 << 25);
  s1 = (s1 + s6 + m2) | 0;
  s12 ^= s1;
  s12 = (s12 >>> 16) | (s12 << 16);
  s11 = (s11 + s12) | 0;
  s6 ^= s11;
  s6 = (s6 >>> 12) | (s6 << 20);
  s1 = (s1 + s6 + m12) | 0;
  s12 ^= s1;
  s12 = (s12 >>> 8) | (s12 << 24);
  s11 = (s11 + s12) | 0;
  s6 ^= s11;
  s6 = (s6 >>> 7) | (s6 << 25);
  s2 = (s2 + s7 + m3) | 0;
  s13 ^= s2;
  s13 = (s13 >>> 16) | (s13 << 16);
  s8 = (s8 + s13) | 0;
  s7 ^= s8;
  s7 = (s7 >>> 12) | (s7 << 20);
  s2 = (s2 + s7 + m4) | 0;
  s13 ^= s2;
  s13 = (s13 >>> 8) | (s13 << 24);
  s8 = (s8 + s13) | 0;
  s7 ^= s8;
  s7 = (s7 >>> 7) | (s7 << 25);
  s3 = (s3 + s4 + m7) | 0;
  s14 ^= s3;
  s14 = (s14 >>> 16) | (s14 << 16);
  s9 = (s9 + s14) | 0;
  s4 ^= s9;
  s4 = (s4 >>> 12) | (s4 << 20);
  s3 = (s3 + s4 + m13) | 0;
  s14 ^= s3;
  s14 = (s14 >>> 8) | (s14 << 24);
  s9 = (s9 + s14) | 0;
  s4 ^= s9;
  s4 = (s4 >>> 7) | (s4 << 25);
  out[0] = s0 ^ s8;
  out[1] = s1 ^ s9;
  out[2] = s2 ^ s10;
  out[3] = s3 ^ s11;
  out[4] = s4 ^ s12;
  out[5] = s5 ^ s13;
  out[6] = s6 ^ s14;
  out[7] = s7 ^ s15;
}

/**
 * Reads up to one 64-byte block as sixteen little-endian words, zero-padded.
 *
 * @param data - The input.
 * @param offset - Where the block starts.
 * @param length - Bytes of the block that carry data.
 * @param words - Where the words go.
 */
function readBlock(data: Uint8Array, offset: number, length: number, words: Uint32Array): void {
  if (length === BLOCK_LEN) {
    for (let word = 0; word < 16; word++) {
      const byte = offset + word * 4;
      words[word] =
        data[byte]! | (data[byte + 1]! << 8) | (data[byte + 2]! << 16) | (data[byte + 3]! << 24);
    }
    return;
  }
  words.fill(0);
  for (let index = 0; index < length; index++) {
    words[index >>> 2]! |= data[offset + index]! << ((index & 3) * 8);
  }
}

/** The last compression of a node, kept back until it is known whether it is the root. */
interface Output {
  readonly cv: Uint32Array;
  readonly block: Uint32Array;
  readonly counter: number;
  readonly blockLength: number;
  readonly flags: number;
}

/**
 * Compresses every block of one chunk but the last, and returns the last as a pending output.
 *
 * @param data - The input.
 * @param start - Where the chunk starts.
 * @param end - Where it ends, at most `CHUNK_LEN` later.
 * @param counter - The chunk's index.
 * @returns {Output} The chunk's final block, not yet compressed.
 */
function chunkOutput(data: Uint8Array, start: number, end: number, counter: number): Output {
  const cv = IV.slice();
  const block = new Uint32Array(16);
  let flags = CHUNK_START;
  let offset = start;
  while (end - offset > BLOCK_LEN) {
    readBlock(data, offset, BLOCK_LEN, block);
    compress(cv, block, counter, BLOCK_LEN, flags, cv);
    flags = 0;
    offset += BLOCK_LEN;
  }
  const blockLength = end - offset;
  readBlock(data, offset, blockLength, block);
  return { cv, block, counter, blockLength, flags: flags | CHUNK_END };
}

/**
 * Compresses a pending output into a chaining value.
 *
 * @param output - The pending output.
 * @param extraFlags - `ROOT` for the root, nothing otherwise.
 * @returns {Uint32Array} The eight-word result.
 */
function finish(output: Readonly<Output>, extraFlags = 0): Uint32Array {
  const out = new Uint32Array(8);
  compress(
    output.cv,
    output.block,
    output.counter,
    output.blockLength,
    output.flags | extraFlags,
    out,
  );
  return out;
}

/**
 * The pending output of a parent node over two child chaining values.
 *
 * @param left - The left child.
 * @param right - The right child.
 * @returns {Output} The parent, not yet compressed.
 */
function parentOutput(left: Uint32Array, right: Uint32Array): Output {
  const block = new Uint32Array(16);
  block.set(left);
  block.set(right, 8);
  return { cv: IV, block, counter: 0, blockLength: BLOCK_LEN, flags: PARENT };
}

/**
 * Computes BLAKE3 with a 32-byte output.
 *
 * @param data - Bytes to hash.
 * @returns {Uint8Array} The hash.
 */
export function blake3(data: Uint8Array): Uint8Array {
  const chunks = Math.max(1, Math.ceil(data.length / CHUNK_LEN));
  const stack: Uint32Array[] = [];
  for (let index = 0; index < chunks - 1; index++) {
    const start = index * CHUNK_LEN;
    let cv = finish(chunkOutput(data, start, start + CHUNK_LEN, index));
    // A completed subtree merges once per trailing zero bit of the number of chunks so far.
    for (let total = index + 1; (total & 1) === 0; total >>>= 1) {
      cv = finish(parentOutput(stack.pop()!, cv));
    }
    stack.push(cv);
  }
  let output = chunkOutput(data, (chunks - 1) * CHUNK_LEN, data.length, chunks - 1);
  while (stack.length > 0) {
    output = parentOutput(stack.pop()!, finish(output));
  }
  const words = finish(output, ROOT);
  const digest = new Uint8Array(32);
  const view = new DataView(digest.buffer);
  for (let word = 0; word < 8; word++) view.setUint32(word * 4, words[word]!, true);
  return digest;
}

export class Blake3 extends FixedHash {
  static readonly key = "blake3";
  protected readonly about = {
    label: "BLAKE3",
    description: "BLAKE3, an extremely fast cryptographic hash, parallelizable, 256-bit output",
    family: "BLAKE",
    category: "cryptographic",
    digestLength: 32,
    securityNote:
      "128-bit security against collisions and preimages, as the BLAKE3 specification states. Merkle tree structure for parallelism",
  } as const;

  /**
   * Computes BLAKE3.
   *
   * @param bytes - Bytes to hash.
   * @returns {Uint8Array} The 32-byte hash.
   */
  protected digest(bytes: Uint8Array): Uint8Array {
    return blake3(bytes);
  }
}
