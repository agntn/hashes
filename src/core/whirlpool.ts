/**
 * Whirlpool (Barreto and Rijmen), the final 2003 revision of ISO/IEC 10118-3: 64-byte blocks
 * through W, a cipher of ten rounds on an 8x8 byte state, in the Miyaguchi-Preneel mode. The S-box
 * comes from the three 4-bit mini-boxes the authors built it from, the diffusion matrix is
 * cir(1, 1, 4, 1, 8, 5, 2, 9), the round constants are rows of the S-box, and the padding ends in a
 * 256-bit length. Whirlpool-0 drew a random S-box and Whirlpool-T kept cir(1, 1, 3, 1, 5, 8, 9, 5),
 * so neither gives these digests.
 */
import { ResumableHasher } from "./resumable.ts";

/** Rounds of W. */
const ROUNDS = 10;
/** The first row of the diffusion matrix. Each row after it turns one byte right. */
const MATRIX = [1, 1, 4, 1, 8, 5, 2, 9] as const;
/** The mini-box E of the S-box, a permutation of 16 nibbles. */
const E: readonly number[] = [1, 11, 9, 12, 13, 6, 15, 3, 14, 8, 7, 4, 10, 2, 5, 0];
/** The mini-box R of the S-box. */
const R: readonly number[] = [7, 12, 11, 13, 14, 4, 9, 15, 6, 3, 8, 10, 2, 5, 1, 0];

/** The eight tables `transform` reads: the matrix times each S-box output, high half first. */
const C = /* @__PURE__ */ new Int32Array(8 * 256 * 2);
/** Each round's constant, the next eight S-box bytes in row 0, high half first. */
const RC = /* @__PURE__ */ new Int32Array(ROUNDS * 2);
/** Whether `C` and `RC` hold the tables yet. */
let built = false;

/** The round key, the cipher state and the next of either, high half first. */
const K = /* @__PURE__ */ new Int32Array(16);
const S = /* @__PURE__ */ new Int32Array(16);
const L = /* @__PURE__ */ new Int32Array(16);

/**
 * Multiplies two bytes in GF(2^8) over x^8 + x^4 + x^3 + x^2 + 1.
 *
 * @param a - A byte.
 * @param b - A small factor from the matrix.
 * @returns {number} The product.
 */
function times(a: number, b: number): number {
  let product = 0;
  for (let x = a, y = b; y > 0; y >>= 1) {
    if (y & 1) product ^= x;
    x = x & 0x80 ? (x << 1) ^ 0x11d : x << 1;
  }
  return product;
}

/** Builds the S-box from E, its inverse and R, then the tables and round constants from it. */
function build(): void {
  const inverse = E.map((_, i) => E.indexOf(i));
  const sbox = new Uint8Array(256);
  for (let u = 0; u < 256; u++) {
    const high = E[u >> 4]!;
    const low = inverse[u & 15]!;
    const mixed = R[high ^ low]!;
    sbox[u] = (E[high ^ mixed]! << 4) | inverse[low ^ mixed]!;
  }
  for (let x = 0; x < 256; x++) {
    let high = 0;
    let low = 0;
    for (let j = 0; j < 4; j++) {
      high = (high << 8) | times(sbox[x]!, MATRIX[j]!);
      low = (low << 8) | times(sbox[x]!, MATRIX[j + 4]!);
    }
    for (let at = x << 1; at < C.length; at += 512) {
      C[at] = high;
      C[at + 1] = low;
      [high, low] = [(high >>> 8) | (low << 24), (low >>> 8) | (high << 24)];
    }
  }
  for (let i = 0; i < ROUNDS * 8; i++) {
    RC[i >> 2] = RC[i >> 2]! | (sbox[i]! << (24 - ((i & 3) << 3)));
  }
  built = true;
}

/**
 * One keyless round of W into `L`: row `i` takes byte `k` of the row `k` above it from table `k`.
 * The eight lookups of a row are spelled out, which took 4 MiB from 20.6 to 36.9 MiB/s.
 *
 * @param from - The state the round reads, `K` or `S`.
 */
function transform(from: Int32Array): void {
  for (let i = 0; i < 16; i += 2) {
    const t0 = (from[i]! >>> 24) << 1;
    const t1 = 0x200 | (((from[(i - 2) & 15]! >>> 16) & 0xff) << 1);
    const t2 = 0x400 | (((from[(i - 4) & 15]! >>> 8) & 0xff) << 1);
    const t3 = 0x600 | ((from[(i - 6) & 15]! & 0xff) << 1);
    const t4 = 0x800 | ((from[((i - 8) & 15) | 1]! >>> 24) << 1);
    const t5 = 0xa00 | (((from[((i - 10) & 15) | 1]! >>> 16) & 0xff) << 1);
    const t6 = 0xc00 | (((from[((i - 12) & 15) | 1]! >>> 8) & 0xff) << 1);
    const t7 = 0xe00 | ((from[((i - 14) & 15) | 1]! & 0xff) << 1);
    L[i] = C[t0]! ^ C[t1]! ^ C[t2]! ^ C[t3]! ^ C[t4]! ^ C[t5]! ^ C[t6]! ^ C[t7]!;
    L[i | 1] =
      C[t0 | 1]! ^
      C[t1 | 1]! ^
      C[t2 | 1]! ^
      C[t3 | 1]! ^
      C[t4 | 1]! ^
      C[t5 | 1]! ^
      C[t6 | 1]! ^
      C[t7 | 1]!;
  }
}

/**
 * Runs one block through W keyed by the state, then XORs in the block and the old state.
 *
 * @param state - The chaining value, high half first.
 * @param block - Bytes holding the block.
 * @param offset - Where the block starts.
 */
function compress(state: Int32Array, block: Uint8Array, offset: number): void {
  for (let i = 0; i < 16; i++) {
    const at = offset + 4 * i;
    const word =
      (block[at]! << 24) | (block[at + 1]! << 16) | (block[at + 2]! << 8) | block[at + 3]!;
    K[i] = state[i]!;
    S[i] = word ^ K[i]!;
    state[i] = S[i]!;
  }
  for (let round = 0; round < ROUNDS; round++) {
    transform(K);
    L[0] = L[0]! ^ RC[round << 1]!;
    L[1] = L[1]! ^ RC[(round << 1) | 1]!;
    K.set(L);
    transform(S);
    for (let i = 0; i < 16; i++) S[i] = L[i]! ^ K[i]!;
  }
  for (let i = 0; i < 16; i++) state[i] = state[i]! ^ S[i]!;
}

/** Whirlpool, the final revision: 512 bits, ten rounds, 0x80 padding and a 256-bit length. */
export class WhirlpoolHasher extends ResumableHasher {
  readonly outputLength = 64;
  protected readonly littleEndian = false;
  protected readonly marker = 0x80;
  protected readonly lengthBytes = 32;
  /** The chaining value, high half first, starting at zero. */
  protected readonly state = new Int32Array(16);

  /**
   * Compresses a block, building the tables first, so a hasher made only to be listed is free.
   *
   * @param block - Bytes holding the block.
   * @param offset - Where the block starts.
   */
  protected compress(block: Uint8Array, offset: number): void {
    if (!built) build();
    compress(this.state, block, offset);
  }
}
