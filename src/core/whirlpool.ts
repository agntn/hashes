/**
 * Whirlpool (Barreto and Rijmen), the final 2003 revision of ISO/IEC 10118-3: 64-byte blocks
 * through W, a cipher of ten rounds on an 8x8 byte state, in the Miyaguchi-Preneel mode. The S-box
 * comes from the three 4-bit mini-boxes the authors built it from, the diffusion matrix is
 * cir(1, 1, 4, 1, 8, 5, 2, 9), the round constants are rows of the S-box, and the padding ends in a
 * 256-bit length. Whirlpool-0 drew a random S-box and Whirlpool-T kept cir(1, 1, 3, 1, 5, 8, 9, 5),
 * so neither gives these digests.
 */
import { HashError } from "./errors.ts";
import { assertBytes, viewOf, wordsToBytes } from "./hasher.ts";
import { ResumableHasher } from "./resumable.ts";

/** Bytes per block. */
const BLOCK = 64;
/** Where the 256-bit length starts in the last block. */
const LENGTH_FIELD = BLOCK - 32;
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

/** The block, the round key, the cipher state and the next of either, high half first. */
const M = /* @__PURE__ */ new Int32Array(16);
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
  const row = new Uint8Array(8);
  for (let x = 0; x < 256; x++) {
    for (let j = 0; j < 8; j++) row[j] = times(sbox[x]!, MATRIX[j]!);
    for (let k = 0; k < 8; k++) {
      const at = ((k << 8) | x) << 1;
      for (let j = 0; j < 8; j++) {
        const byte = row[(j - k) & 7]!;
        C[at + (j >> 2)] = C[at + (j >> 2)]! | (byte << (24 - ((j & 3) << 3)));
      }
    }
  }
  for (let i = 0; i < ROUNDS * 8; i++) {
    RC[i >> 2] = RC[i >> 2]! | (sbox[i]! << (24 - ((i & 3) << 3)));
  }
  built = true;
}

/**
 * One keyless round of W into `L`: row `i` takes byte `k` of the row `k` above it from table `k`.
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
 * Runs one block through W keyed by the state, then XORs the block and the old state in.
 *
 * @param state - The chaining value, high half first.
 * @param block - Bytes holding the block.
 * @param offset - Where the block starts.
 */
function compress(state: Int32Array, block: Uint8Array, offset: number): void {
  for (let i = 0; i < 16; i++) {
    const at = offset + 4 * i;
    M[i] = (block[at]! << 24) | (block[at + 1]! << 16) | (block[at + 2]! << 8) | block[at + 3]!;
    K[i] = state[i]!;
    S[i] = M[i]! ^ K[i]!;
  }
  for (let round = 0; round < ROUNDS; round++) {
    transform(K);
    L[0] = L[0]! ^ RC[round << 1]!;
    L[1] = L[1]! ^ RC[(round << 1) | 1]!;
    K.set(L);
    transform(S);
    for (let i = 0; i < 16; i++) S[i] = L[i]! ^ K[i]!;
  }
  for (let i = 0; i < 16; i++) state[i] = state[i]! ^ S[i]! ^ M[i]!;
}

/**
 * Writes the bit length big-endian before `end`. The 24 bytes above it stay zero.
 *
 * @param out - The block or padding being written.
 * @param end - Where the length field ends.
 * @param length - Bytes hashed.
 */
function writeLength(out: Uint8Array, end: number, length: number): void {
  const high = Math.floor(length / 0x2000_0000);
  const low = (length % 0x2000_0000) * 8;
  for (let i = 0; i < 4; i++) {
    out[end - 8 + i] = high >>> (24 - 8 * i);
    out[end - 4 + i] = low >>> (24 - 8 * i);
  }
}

/** Whirlpool, the final revision: 512 bits, ten rounds, 0x80 padding and a 256-bit length. */
export class WhirlpoolHasher extends ResumableHasher {
  readonly blockLength = BLOCK;
  readonly outputLength = 64;
  /** The chaining value, high half first, starting at zero. */
  private readonly state = new Int32Array(16);
  /** The partial block not compressed yet. */
  private readonly buffer = new Uint8Array(BLOCK);
  /** Bytes waiting in the buffer. */
  private position = 0;
  /** Bytes absorbed so far. */
  private length = 0;

  update(data: Uint8Array): this {
    assertBytes(data, "data");
    const { buffer } = this;
    const length = data.length;
    let position = this.position;
    let offset = 0;
    this.length += length;
    if (position > 0) {
      while (offset < length && position < BLOCK) buffer[position++] = data[offset++]!;
      if (position < BLOCK) {
        this.position = position;
        return this;
      }
      this.compressBlock(buffer, 0);
      position = 0;
    }
    for (; length - offset >= BLOCK; offset += BLOCK) this.compressBlock(data, offset);
    while (offset < length) buffer[position++] = data[offset++]!;
    this.position = position;
    return this;
  }

  digestInto(out: Uint8Array): void {
    const { buffer } = this;
    let position = this.position;
    buffer[position++] = 0x80;
    if (position > LENGTH_FIELD) {
      buffer.fill(0, position);
      this.compressBlock(buffer, 0);
      position = 0;
    }
    buffer.fill(0, position, BLOCK - 8);
    writeLength(buffer, BLOCK, this.length);
    this.compressBlock(buffer, 0);
    wordsToBytes(this.state, out, this.outputLength, false);
  }

  padding(length: number): Uint8Array {
    const least = 1 + BLOCK - LENGTH_FIELD;
    const size = least + ((BLOCK - ((length + least) % BLOCK)) % BLOCK);
    const out = new Uint8Array(size);
    out[0] = 0x80;
    writeLength(out, size, length);
    return out;
  }

  resume(digest: Uint8Array, length: number): this {
    assertBytes(digest, "digest");
    const { state } = this;
    if (digest.length !== this.outputLength || !(length >= 0 && length % BLOCK === 0)) {
      throw new HashError(
        `resume takes a ${this.outputLength}-byte digest and a multiple of ${BLOCK} bytes`,
      );
    }
    const view = viewOf(digest);
    for (let i = 0; i < state.length; i++) state[i] = view.getInt32(i * 4, false);
    this.position = 0;
    this.length = length;
    return this;
  }

  load(source: this): this {
    this.state.set(source.state);
    this.buffer.set(source.buffer);
    this.position = source.position;
    this.length = source.length;
    return this;
  }

  /**
   * Compresses a block, building the tables first, so a hasher made only to be listed is free.
   *
   * @param block - Bytes holding the block.
   * @param offset - Where the block starts.
   */
  private compressBlock(block: Uint8Array, offset: number): void {
    if (!built) build();
    compress(this.state, block, offset);
  }
}
