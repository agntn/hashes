/**
 * HAVAL (Zheng, Pieprzyk and Seberry, AUSCRYPT '92): 128-byte blocks run through three, four or
 * five passes of 32 steps over eight little-endian words, then the state folded down to the
 * fingerprint length. Its starting words and step constants are the digits of π that open
 * Blowfish too.
 */
import { InvalidOptionError } from "./errors.ts";
import { piWords } from "./pi.ts";
import { ResumableHasher } from "./resumable.ts";

/** Passes HAVAL defines. */
export const HAVAL_PASSES = [3, 4, 5] as const;
/** Fingerprint lengths in bits. */
export const HAVAL_BITS = [128, 160, 192, 224, 256] as const;
/** A pass count. */
export type HavalPasses = (typeof HAVAL_PASSES)[number];
/** A fingerprint length in bits. */
export type HavalBits = (typeof HAVAL_BITS)[number];
/** What the reference `haval.h` builds unless told otherwise. */
export const HAVAL_DEFAULT_PASSES: HavalPasses = 3;
export const HAVAL_DEFAULT_BITS: HavalBits = 128;

/** Bytes per block. */
const BLOCK = 128;
/** The version the padding names. There has only ever been 1. */
const VERSION = 1;

/** A Boolean function of the seven words before the one a step writes. The paper's five follow. */
type BooleanFunction = (
  x6: number,
  x5: number,
  x4: number,
  x3: number,
  x2: number,
  x1: number,
  x0: number,
) => number;

const FUNCTIONS: readonly BooleanFunction[] = [
  (x6, x5, x4, x3, x2, x1, x0) => (x1 & (x0 ^ x4)) ^ (x2 & x5) ^ (x3 & x6) ^ x0,
  (x6, x5, x4, x3, x2, x1, x0) =>
    (x2 & ((x1 & ~x3) ^ (x4 & x5) ^ x6 ^ x0)) ^ (x4 & (x1 ^ x5)) ^ (x3 & x5) ^ x0,
  (x6, x5, x4, x3, x2, x1, x0) => (x3 & ((x1 & x2) ^ x6 ^ x0)) ^ (x1 & x4) ^ (x2 & x5) ^ x0,
  (x6, x5, x4, x3, x2, x1, x0) =>
    (x4 & ((x5 & ~x2) ^ (x3 & ~x6) ^ x1 ^ x6 ^ x0)) ^ (x3 & ((x1 & x2) ^ x5 ^ x6)) ^ (x2 & x6) ^ x0,
  (x6, x5, x4, x3, x2, x1, x0) => (x0 & ((x1 & x2 & x3) ^ ~x5)) ^ (x1 & x4) ^ (x2 & x5) ^ (x3 & x6),
];

/** The word each argument of a Boolean function reads, x6 first. */
type Permutation = readonly [number, number, number, number, number, number, number];

/** Which word each function argument reads, pass by pass, for 3, 4 and 5 passes. */
const PERMUTATIONS: readonly (readonly Permutation[])[] = [
  [
    [1, 0, 3, 5, 6, 2, 4],
    [4, 2, 1, 0, 5, 3, 6],
    [6, 1, 2, 3, 4, 5, 0],
  ],
  [
    [2, 6, 1, 4, 5, 3, 0],
    [3, 5, 2, 0, 1, 6, 4],
    [1, 4, 3, 6, 0, 2, 5],
    [6, 4, 0, 5, 2, 1, 3],
  ],
  [
    [3, 4, 1, 0, 5, 2, 6],
    [6, 2, 1, 0, 3, 4, 5],
    [2, 6, 0, 4, 3, 1, 5],
    [1, 5, 3, 2, 0, 4, 6],
    [2, 5, 0, 6, 4, 3, 1],
  ],
];

/** The order each pass reads the block's 32 words in. */
const ORDERS: readonly Uint8Array[] = [
  /* @__PURE__ */ Uint8Array.from({ length: 32 }, (_, i) => i),
  /* @__PURE__ */ new Uint8Array([
    5, 14, 26, 18, 11, 28, 7, 16, 0, 23, 20, 22, 1, 10, 4, 8, 30, 3, 21, 9, 17, 24, 29, 6, 19, 12,
    15, 13, 2, 25, 31, 27,
  ]),
  /* @__PURE__ */ new Uint8Array([
    19, 9, 4, 20, 28, 17, 8, 22, 29, 14, 25, 12, 24, 30, 16, 26, 31, 15, 7, 3, 1, 0, 18, 27, 13, 6,
    21, 10, 23, 11, 5, 2,
  ]),
  /* @__PURE__ */ new Uint8Array([
    24, 4, 0, 14, 2, 7, 28, 23, 26, 6, 30, 20, 18, 25, 19, 3, 22, 11, 31, 21, 8, 27, 12, 9, 1, 29,
    5, 15, 17, 10, 16, 13,
  ]),
  /* @__PURE__ */ new Uint8Array([
    27, 3, 21, 26, 17, 11, 20, 29, 19, 0, 12, 7, 13, 8, 31, 10, 5, 9, 14, 30, 18, 6, 28, 24, 2, 23,
    16, 22, 4, 1, 25, 15,
  ]),
];

/** For each word kept: masks over words 7 to 4, then how far to turn the field right. */
type Fold = readonly [number, number, number, number, number];

/** The folds of the reference implementation, by fingerprint length. */
const FOLDS: Readonly<Record<Exclude<HavalBits, 256>, readonly Fold[]>> = {
  128: [
    [0x00_00_00_ff, 0xff_00_00_00, 0x00_ff_00_00, 0x00_00_ff_00, 8],
    [0x00_00_ff_00, 0x00_00_00_ff, 0xff_00_00_00, 0x00_ff_00_00, 16],
    [0x00_ff_00_00, 0x00_00_ff_00, 0x00_00_00_ff, 0xff_00_00_00, 24],
    [0xff_00_00_00, 0x00_ff_00_00, 0x00_00_ff_00, 0x00_00_00_ff, 0],
  ],
  160: [
    [0x00_00_00_3f, 0xfe_00_00_00, 0x01_f8_00_00, 0, 19],
    [0x00_00_0f_c0, 0x00_00_00_3f, 0xfe_00_00_00, 0, 25],
    [0x00_07_f0_00, 0x00_00_0f_c0, 0x00_00_00_3f, 0, 0],
    [0x01_f8_00_00, 0x00_07_f0_00, 0x00_00_0f_c0, 0, 6],
    [0xfe_00_00_00, 0x01_f8_00_00, 0x00_07_f0_00, 0, 12],
  ],
  192: [
    [0x00_00_00_1f, 0xfc_00_00_00, 0, 0, 26],
    [0x00_00_03_e0, 0x00_00_00_1f, 0, 0, 0],
    [0x00_00_fc_00, 0x00_00_03_e0, 0, 0, 5],
    [0x00_1f_00_00, 0x00_00_fc_00, 0, 0, 10],
    [0x03_e0_00_00, 0x00_1f_00_00, 0, 0, 16],
    [0xfc_00_00_00, 0x03_e0_00_00, 0, 0, 21],
  ],
  224: [
    [0xf8_00_00_00, 0, 0, 0, 27],
    [0x07_c0_00_00, 0, 0, 0, 22],
    [0x00_3c_00_00, 0, 0, 0, 18],
    [0x00_03_e0_00, 0, 0, 0, 13],
    [0x00_00_1e_00, 0, 0, 0, 9],
    [0x00_00_01_f0, 0, 0, 0, 4],
    [0x00_00_00_0f, 0, 0, 0, 0],
  ],
};

/** The block's words, shared: hashing is synchronous. */
const WORDS = /* @__PURE__ */ new Int32Array(32);
/** The eight words a block's passes work on, shared the same way. */
const REGISTERS = /* @__PURE__ */ new Int32Array(8);

/** π's first 8 words start the state; the next 128 are the constants of passes 2 to 5. */
let piTable: Int32Array | undefined;

/**
 * Lays π's words out once: the state, 32 zeros for pass 1, then a constant per later step.
 *
 * @returns {Int32Array} 168 words.
 */
function table(): Int32Array {
  if (piTable) return piTable;
  const words = piWords(136);
  piTable = new Int32Array(168);
  piTable.set(words.subarray(0, 8));
  piTable.set(words.subarray(8), 40);
  return piTable;
}

/**
 * Turns a word right by `n` bits.
 *
 * @param x - A 32-bit word.
 * @param n - Bits to rotate by.
 * @returns {number} The rotated word.
 */
function rotr(x: number, n: number): number {
  return (x >>> n) | (x << (32 - n));
}

/** HAVAL. Only the 256-bit fingerprint prints the whole state, so only it extends. */
export class HavalHasher extends ResumableHasher {
  readonly outputLength: number;
  /** Passes over each block. */
  readonly passes: HavalPasses;
  /** Fingerprint length in bits. */
  readonly bits: HavalBits;
  protected readonly littleEndian = true;
  protected readonly marker = 0x01;
  /** Ten bytes: the version, passes and fingerprint length packed into two, then the bit count. */
  protected readonly lengthBytes = 10;
  /** The eight chaining words. */
  protected readonly state: Int32Array;
  /** π's words and step constants. */
  private readonly table = table();

  /**
   * @param passes - 3, 4 or 5. Default: 3, as the reference implementation's `haval.h`.
   * @param bits - 128, 160, 192, 224 or 256. Default: 128, as `haval.h` again.
   */
  constructor(passes: HavalPasses = HAVAL_DEFAULT_PASSES, bits: HavalBits = HAVAL_DEFAULT_BITS) {
    super(BLOCK);
    if (!HAVAL_PASSES.includes(passes)) {
      throw new InvalidOptionError("passes", passes, `use one of ${HAVAL_PASSES.join(", ")}`);
    }
    if (!HAVAL_BITS.includes(bits)) {
      throw new InvalidOptionError("bits", bits, `use one of ${HAVAL_BITS.join(", ")}`);
    }
    this.passes = passes;
    this.bits = bits;
    this.outputLength = bits / 8;
    this.state = this.table.slice(0, 8);
  }

  /**
   * Packs the version, passes and fingerprint length into the two bytes before the bit count.
   *
   * @param out - The block or padding being written.
   * @param at - Where the bit count starts.
   */
  protected override writeFields(out: Uint8Array, at: number): void {
    const { bits } = this;
    out[at - 2] = ((bits & 3) << 6) | (this.passes << 3) | VERSION;
    out[at - 1] = bits >>> 2;
  }

  /**
   * Runs one block through every pass and adds the result to the state.
   *
   * @param block - Bytes holding the block.
   * @param offset - Where the block starts.
   */
  protected compress(block: Uint8Array, offset: number): void {
    const { state } = this;
    for (let i = 0; i < 32; i++) {
      const at = offset + 4 * i;
      WORDS[i] =
        block[at]! | (block[at + 1]! << 8) | (block[at + 2]! << 16) | (block[at + 3]! << 24);
    }
    REGISTERS.set(state);
    for (let pass = 0; pass < this.passes; pass++) this.pass(pass);
    for (let i = 0; i < 8; i++) state[i] = (state[i]! + REGISTERS[i]!) | 0;
  }

  /**
   * Runs the 32 steps of one pass. Step `j` writes register `7 - j` mod 8 from the others.
   *
   * @param index - The pass, from 0.
   */
  private pass(index: number): void {
    const t = REGISTERS;
    const f = FUNCTIONS[index]!;
    const order = ORDERS[index]!;
    const [p6, p5, p4, p3, p2, p1, p0] = PERMUTATIONS[this.passes - 3]![index]!;
    const constants = this.table;
    const base = 8 + 32 * index;
    for (let j = 0; j < 32; j++) {
      const value = f(
        t[(p6 - j) & 7]!,
        t[(p5 - j) & 7]!,
        t[(p4 - j) & 7]!,
        t[(p3 - j) & 7]!,
        t[(p2 - j) & 7]!,
        t[(p1 - j) & 7]!,
        t[(p0 - j) & 7]!,
      );
      const target = (7 - j) & 7;
      t[target] =
        (rotr(value, 7) + rotr(t[target]!, 11) + WORDS[order[j]!]! + constants[base + j]!) | 0;
    }
  }

  /** Folds the eight words down to `bits`, adding fields of the dropped words to the kept ones. */
  protected override finish(): void {
    if (this.bits === 256) return;
    const s = this.state;
    const [w7, w6, w5, w4] = [s[7]!, s[6]!, s[5]!, s[4]!];
    let i = 0;
    for (const [m7, m6, m5, m4, amount] of FOLDS[this.bits]) {
      const field = (w7 & m7) | (w6 & m6) | (w5 & m5) | (w4 & m4);
      s[i] = (s[i]! + rotr(field, amount)) | 0;
      i++;
    }
  }
}
