/** Argon2 (RFC 9106), version 0x13: Argon2d, Argon2i and Argon2id over BLAKE2b. */
import { Blake2bHasher } from "./blake2b.ts";
import { InvalidOptionError } from "./errors.ts";
import { assertBytes } from "./hasher.ts";

/** Cost and output of one Argon2 call. */
export interface Argon2Parameters {
  /** Memory in KiB, at least 8 per lane. */
  memory: number;
  /** Passes over the memory. */
  iterations: number;
  /** Lanes, 1 to 2^24 - 1. */
  parallelism: number;
  /** Output bytes, at least 4. */
  keyLength: number;
  /** Key K, mixed into the first hash. Default: none. */
  secret?: Uint8Array;
  /** Associated data X, mixed into the first hash. Default: none. */
  associatedData?: Uint8Array;
}

/** The RFC's variant numbers y, which the first hash and the address blocks carry. */
const ARGON2D = 0;
const ARGON2I = 1;
const ARGON2ID = 2;

const VERSION = 0x13;
const SYNC_POINTS = 4;
/** Words in a 1 KiB block: 128 64-bit words as low and high halves. */
const BLOCK_WORDS = 256;
const MAX_UINT32 = 0xffff_ffff;

/**
 * Checks the parameters against RFC 9106 before any memory is taken.
 *
 * @param parameters - Cost, output and the optional inputs.
 */
function assertParameters(parameters: Readonly<Argon2Parameters>): void {
  if (typeof parameters !== "object" || parameters === null) {
    throw new InvalidOptionError("parameters", parameters, "must be an object");
  }
  const { memory, parallelism } = parameters;
  for (const [name, floor, ceiling] of BOUNDS) {
    const value = parameters[name];
    if (!Number.isInteger(value) || value < floor || value > ceiling) {
      throw new InvalidOptionError(name, value, `must be an integer from ${floor} to ${ceiling}`);
    }
  }
  if (memory < 8 * parallelism) {
    throw new InvalidOptionError("memory", memory, "must be at least 8 KiB per lane");
  }
  assertOptionalBytes(parameters);
}

/**
 * Refuses a secret or associated data that is not a `Uint8Array`.
 *
 * @param parameters - Cost, output and the optional inputs.
 */
function assertOptionalBytes(parameters: Readonly<Argon2Parameters>): void {
  for (const name of ["secret", "associatedData"] as const) {
    const value = parameters[name];
    if (value !== undefined) assertBytes(value, name);
  }
}

/** Each numeric parameter with its RFC 9106 range; parallelism first, since memory needs it. */
const BOUNDS = [
  ["parallelism", 1, 0xff_ffff],
  ["iterations", 1, MAX_UINT32],
  ["keyLength", 4, MAX_UINT32],
  ["memory", 8, MAX_UINT32],
] as const;

/**
 * Encodes an unsigned 32-bit integer as four little-endian bytes.
 *
 * @param value - The integer.
 * @returns {Uint8Array} Its bytes.
 */
function le32(value: number): Uint8Array {
  return new Uint8Array(new Uint32Array([value]).buffer);
}

/**
 * H', the variable-length hash: BLAKE2b up to 64 bytes, a chain of 64-byte BLAKE2b past that,
 * keeping the first 32 bytes of each link and all of the last.
 *
 * @param length - Output bytes.
 * @param input - The input.
 * @returns {Uint8Array} The output.
 */
function hashLong(length: number, input: Uint8Array): Uint8Array {
  const first = new Blake2bHasher(Math.min(length, 64)).update(le32(length)).update(input);
  if (length <= 64) return first.digest();
  const out = new Uint8Array(length);
  let link = first.digest();
  out.set(link.subarray(0, 32));
  let offset = 32;
  while (length - offset > 64) {
    link = new Blake2bHasher(64).update(link).digest();
    out.set(link.subarray(0, 32), offset);
    offset += 32;
  }
  out.set(new Blake2bHasher(length - offset).update(link).digest(), offset);
  return out;
}

/**
 * The high 32 bits of the product of two unsigned 32-bit integers, from 16-bit halves.
 *
 * @param a - First factor.
 * @param b - Second factor.
 * @returns {number} The high word, unsigned.
 */
function mulHigh(a: number, b: number): number {
  const al = a & 0xffff;
  const ah = a >>> 16;
  const bl = b & 0xffff;
  const bh = b >>> 16;
  const lh = al * bh;
  const hl = ah * bl;
  const middle = ((al * bl) >>> 16) + (lh & 0xffff) + (hl & 0xffff);
  return ah * bh + (lh >>> 16) + (hl >>> 16) + (middle >>> 16);
}

/**
 * GB with BlaMka's multiply, a = a + b + 2 * lo(a) * lo(b) and so on, rotating by 32, 24, 16, 63.
 * Word `i` of `v` is a low half at `2 * i` and a high half after it.
 *
 * @param v - The block being permuted.
 * @param a - Index of a.
 * @param b - Index of b.
 * @param c - Index of c.
 * @param d - Index of d.
 */
function mix(v: Uint32Array, a: number, b: number, c: number, d: number): void {
  let al = v[2 * a]!;
  let ah = v[2 * a + 1]!;
  let bl = v[2 * b]!;
  let bh = v[2 * b + 1]!;
  let cl = v[2 * c]!;
  let ch = v[2 * c + 1]!;
  let dl = v[2 * d]!;
  let dh = v[2 * d + 1]!;
  let sum = 0;
  let product = 0;
  let t = 0;

  product = Math.imul(al, bl) >>> 0;
  sum = al + bl + ((product << 1) >>> 0);
  ah =
    (ah + bh + ((mulHigh(al, bl) << 1) | (product >>> 31)) + Math.floor(sum / 0x1_0000_0000)) >>> 0;
  al = sum >>> 0;
  t = (dl ^ al) >>> 0;
  dl = (dh ^ ah) >>> 0;
  dh = t;
  product = Math.imul(cl, dl) >>> 0;
  sum = cl + dl + ((product << 1) >>> 0);
  ch =
    (ch + dh + ((mulHigh(cl, dl) << 1) | (product >>> 31)) + Math.floor(sum / 0x1_0000_0000)) >>> 0;
  cl = sum >>> 0;
  t = bl ^ cl;
  bh ^= ch;
  bl = ((t >>> 24) | (bh << 8)) >>> 0;
  bh = ((bh >>> 24) | (t << 8)) >>> 0;
  product = Math.imul(al, bl) >>> 0;
  sum = al + bl + ((product << 1) >>> 0);
  ah =
    (ah + bh + ((mulHigh(al, bl) << 1) | (product >>> 31)) + Math.floor(sum / 0x1_0000_0000)) >>> 0;
  al = sum >>> 0;
  t = dl ^ al;
  dh ^= ah;
  dl = ((t >>> 16) | (dh << 16)) >>> 0;
  dh = ((dh >>> 16) | (t << 16)) >>> 0;
  product = Math.imul(cl, dl) >>> 0;
  sum = cl + dl + ((product << 1) >>> 0);
  ch =
    (ch + dh + ((mulHigh(cl, dl) << 1) | (product >>> 31)) + Math.floor(sum / 0x1_0000_0000)) >>> 0;
  cl = sum >>> 0;
  t = bl ^ cl;
  bh ^= ch;
  bl = ((t << 1) | (bh >>> 31)) >>> 0;
  bh = ((bh << 1) | (t >>> 31)) >>> 0;

  v[2 * a] = al;
  v[2 * a + 1] = ah;
  v[2 * b] = bl;
  v[2 * b + 1] = bh;
  v[2 * c] = cl;
  v[2 * c + 1] = ch;
  v[2 * d] = dl;
  v[2 * d + 1] = dh;
}

/**
 * P, the permutation of sixteen 64-bit words, taken at word indices `i0` to `i15` of `v`.
 *
 * @param v - The block being permuted.
 * @param i - The sixteen word indices.
 */
function permute(v: Uint32Array, i: readonly number[]): void {
  mix(v, i[0]!, i[4]!, i[8]!, i[12]!);
  mix(v, i[1]!, i[5]!, i[9]!, i[13]!);
  mix(v, i[2]!, i[6]!, i[10]!, i[14]!);
  mix(v, i[3]!, i[7]!, i[11]!, i[15]!);
  mix(v, i[0]!, i[5]!, i[10]!, i[15]!);
  mix(v, i[1]!, i[6]!, i[11]!, i[12]!);
  mix(v, i[2]!, i[7]!, i[8]!, i[13]!);
  mix(v, i[3]!, i[4]!, i[9]!, i[14]!);
}

/** The word indices P runs on: eight rows of sixteen words, then eight columns of pairs. */
const ROWS: readonly (readonly number[])[] = /* @__PURE__ */ Array.from({ length: 8 }, (_, row) =>
  Array.from({ length: 16 }, (_, k) => 16 * row + k),
);
const COLUMNS: readonly (readonly number[])[] = /* @__PURE__ */ Array.from(
  { length: 8 },
  (_, column) => Array.from({ length: 16 }, (_, k) => 2 * column + 16 * (k >> 1) + (k & 1)),
);

/**
 * G: P over the rows, then the columns, of R = X ^ Y, XORed back with R. With `xor` the result
 * also keeps what `out` held, as every pass after the first does.
 *
 * @param x - First input block.
 * @param y - Second input block.
 * @param out - Output block, which may share memory with neither input.
 * @param r - 256 words of scratch.
 * @param xor - Whether to keep what `out` held.
 */
function compress(
  x: Uint32Array,
  y: Uint32Array,
  out: Uint32Array,
  r: Uint32Array,
  xor: boolean,
): void {
  for (let k = 0; k < BLOCK_WORDS; k++) r[k] = x[k]! ^ y[k]!;
  if (xor) {
    for (let k = 0; k < BLOCK_WORDS; k++) out[k] = out[k]! ^ r[k]!;
  } else {
    out.set(r);
  }
  for (const row of ROWS) permute(r, row);
  for (const column of COLUMNS) permute(r, column);
  for (let k = 0; k < BLOCK_WORDS; k++) out[k] = out[k]! ^ r[k]!;
}

/** The memory of one call and the numbers that lay it out. */
interface Matrix {
  readonly type: number;
  readonly iterations: number;
  readonly parallelism: number;
  readonly segmentLength: number;
  readonly laneLength: number;
  /** Every block, lane after lane, 256 words each. */
  readonly blocks: Uint32Array;
  /** The input block of the address generator, and the 128 index pairs it last gave. */
  readonly input: Uint32Array;
  readonly address: Uint32Array;
  readonly scratch: Uint32Array;
  /** An all-zero block, the first input of G in the address generator. */
  readonly zero: Uint32Array;
}

/**
 * H0, the first hash: the parameters, the variant and every input with its length.
 *
 * @param type - The variant number y.
 * @param password - The password P.
 * @param salt - The salt S.
 * @param parameters - Cost, output and the optional inputs.
 * @returns {Uint8Array} 64 bytes, then eight zero bytes for the block and lane numbers.
 */
function firstHash(
  type: number,
  password: Uint8Array,
  salt: Uint8Array,
  parameters: Readonly<Argon2Parameters>,
): Uint8Array {
  const { memory, iterations, parallelism, keyLength } = parameters;
  const h0 = new Blake2bHasher(64);
  for (const value of [parallelism, keyLength, memory, iterations, VERSION, type]) {
    h0.update(le32(value));
  }
  const empty = new Uint8Array(0);
  for (const part of [
    password,
    salt,
    parameters.secret ?? empty,
    parameters.associatedData ?? empty,
  ]) {
    h0.update(le32(part.length)).update(part);
  }
  const seed = new Uint8Array(72);
  seed.set(h0.digest());
  return seed;
}

/**
 * Fills the first two blocks of each lane from H0.
 *
 * @param matrix - The memory.
 * @param seed - H0 with room for the block and lane numbers.
 */
function fillFirstBlocks(matrix: Readonly<Matrix>, seed: Uint8Array): void {
  const view = new DataView(seed.buffer);
  for (let lane = 0; lane < matrix.parallelism; lane++) {
    view.setUint32(68, lane, true);
    for (let column = 0; column < 2; column++) {
      view.setUint32(64, column, true);
      const bytes = new DataView(hashLong(1024, seed).buffer);
      const offset = (lane * matrix.laneLength + column) * BLOCK_WORDS;
      for (let k = 0; k < BLOCK_WORDS; k++) {
        matrix.blocks[offset + k] = bytes.getUint32(4 * k, true);
      }
    }
  }
}

/**
 * The next 128 index pairs for data-independent addressing: G(0, G(0, input)) with the counter
 * raised by one.
 *
 * @param matrix - The memory, whose `address` block gets the pairs.
 */
function nextAddresses(matrix: Readonly<Matrix>): void {
  const { input, address, scratch, zero } = matrix;
  input[12] = (input[12]! + 1) >>> 0;
  compress(zero, input, address, scratch, false);
  compress(zero, address.slice(), address, scratch, false);
}

/**
 * Maps J1 into the blocks a reference may take, so recent blocks come up more often than old ones.
 *
 * @param matrix - The memory.
 * @param position - Pass, slice and index in the segment.
 * @param sameLane - Whether the reference lane is the current one.
 * @param j1 - The low word of the pseudo-random pair.
 * @returns {number} The column of the reference block.
 */
function referenceColumn(
  matrix: Readonly<Matrix>,
  position: Readonly<{ pass: number; slice: number; index: number }>,
  sameLane: boolean,
  j1: number,
): number {
  const { segmentLength, laneLength } = matrix;
  const { pass, slice, index } = position;
  const finished = pass === 0 ? slice * segmentLength : laneLength - segmentLength;
  const area = sameLane ? finished + index - 1 : finished - (index === 0 ? 1 : 0);
  const relative = area - 1 - mulHigh(area, mulHigh(j1, j1));
  const start = pass === 0 || slice === SYNC_POINTS - 1 ? 0 : (slice + 1) * segmentLength;
  return (start + relative) % laneLength;
}

/**
 * Starts the address generator of a segment that reads memory independently of the data.
 *
 * @param matrix - The memory.
 * @param pass - The pass.
 * @param slice - The slice.
 * @param lane - The lane.
 * @returns {boolean} Whether this segment takes its references from the generator.
 */
function startAddresses(matrix: Readonly<Matrix>, pass: number, slice: number, lane: number) {
  const { type, input } = matrix;
  if (type !== ARGON2I && !(type === ARGON2ID && pass === 0 && slice < 2)) return false;
  const blockCount = matrix.laneLength * matrix.parallelism;
  input.fill(0);
  input.set([pass, 0, lane, 0, slice, 0, blockCount, 0, matrix.iterations, 0, type]);
  nextAddresses(matrix);
  return true;
}

/**
 * Picks the block a new block mixes in, from the generator or from the previous block's first word.
 *
 * @param matrix - The memory.
 * @param position - Pass, slice, lane and index in the segment.
 * @param previous - The previous block, or -1 to read the generator.
 * @returns {number} The reference block.
 */
function referenceBlock(
  matrix: Readonly<Matrix>,
  position: Readonly<{ pass: number; slice: number; lane: number; index: number }>,
  previous: number,
): number {
  const { pass, slice, lane, index } = position;
  const pair = previous < 0 ? matrix.address : matrix.blocks;
  const at = previous < 0 ? 2 * (index % 128) : previous * BLOCK_WORDS;
  const refLane = pass === 0 && slice === 0 ? lane : pair[at + 1]! % matrix.parallelism;
  return (
    refLane * matrix.laneLength + referenceColumn(matrix, position, refLane === lane, pair[at]!)
  );
}

/**
 * One block of the memory as a view.
 *
 * @param blocks - The memory.
 * @param index - The block.
 * @returns {Uint32Array} Its 256 words.
 */
function block(blocks: Uint32Array, index: number): Uint32Array {
  return blocks.subarray(index * BLOCK_WORDS, (index + 1) * BLOCK_WORDS);
}

/**
 * Computes one segment: the blocks of one lane within one slice of one pass.
 *
 * @param matrix - The memory.
 * @param pass - The pass.
 * @param slice - The slice.
 * @param lane - The lane.
 */
function fillSegment(matrix: Readonly<Matrix>, pass: number, slice: number, lane: number): void {
  const { segmentLength, laneLength, blocks } = matrix;
  const independent = startAddresses(matrix, pass, slice, lane);
  const start = pass === 0 && slice === 0 ? 2 : 0;
  for (let index = start; index < segmentLength; index++) {
    const column = slice * segmentLength + index;
    const current = lane * laneLength + column;
    const previous = column === 0 ? current + laneLength - 1 : current - 1;
    if (independent && index % 128 === 0 && index > start) nextAddresses(matrix);
    const position = { pass, slice, lane, index };
    const reference = referenceBlock(matrix, position, independent ? -1 : previous);
    compress(
      block(blocks, previous),
      block(blocks, reference),
      block(blocks, current),
      matrix.scratch,
      pass > 0,
    );
  }
}

/**
 * Derives a key with one Argon2 variant.
 *
 * @param type - The variant number y.
 * @param password - The password P.
 * @param salt - The salt S, at least 8 bytes.
 * @param parameters - Cost, output and the optional inputs.
 * @returns {Uint8Array} The tag.
 */
function argon2(
  type: number,
  password: Uint8Array,
  salt: Uint8Array,
  parameters: Readonly<Argon2Parameters>,
): Uint8Array {
  assertBytes(password, "password");
  assertBytes(salt, "salt");
  if (salt.length < 8) {
    throw new InvalidOptionError("salt", `${salt.length} bytes`, "must be at least 8 bytes");
  }
  assertParameters(parameters);
  const { iterations, parallelism } = parameters;
  const segmentLength = Math.floor(parameters.memory / (SYNC_POINTS * parallelism));
  const laneLength = segmentLength * SYNC_POINTS;
  const matrix: Matrix = {
    type,
    iterations,
    parallelism,
    segmentLength,
    laneLength,
    blocks: new Uint32Array(laneLength * parallelism * BLOCK_WORDS),
    input: new Uint32Array(BLOCK_WORDS),
    address: new Uint32Array(BLOCK_WORDS),
    scratch: new Uint32Array(BLOCK_WORDS),
    zero: new Uint32Array(BLOCK_WORDS),
  };
  fillFirstBlocks(matrix, firstHash(type, password, salt, parameters));
  for (let pass = 0; pass < iterations; pass++) {
    for (let slice = 0; slice < SYNC_POINTS; slice++) {
      for (let lane = 0; lane < parallelism; lane++) fillSegment(matrix, pass, slice, lane);
    }
  }
  const last = new Uint32Array(BLOCK_WORDS);
  for (let lane = 0; lane < parallelism; lane++) {
    const end = (lane + 1) * laneLength * BLOCK_WORDS;
    for (let k = 0; k < BLOCK_WORDS; k++)
      last[k] = last[k]! ^ matrix.blocks[end - BLOCK_WORDS + k]!;
  }
  return hashLong(parameters.keyLength, new Uint8Array(last.buffer));
}

/**
 * Derives a key with Argon2id, data-independent for the first half pass and data-dependent after.
 *
 * @param password - The password.
 * @param salt - The salt, at least 8 bytes.
 * @param parameters - Memory in KiB, iterations, parallelism, key length, and an optional secret
 * and associated data.
 * @returns {Uint8Array} The derived key.
 */
export function argon2id(
  password: Uint8Array,
  salt: Uint8Array,
  parameters: Readonly<Argon2Parameters>,
): Uint8Array {
  return argon2(ARGON2ID, password, salt, parameters);
}

/**
 * Derives a key with Argon2i, whose memory reads never depend on the password.
 *
 * @param password - The password.
 * @param salt - The salt, at least 8 bytes.
 * @param parameters - Memory in KiB, iterations, parallelism, key length, and an optional secret
 * and associated data.
 * @returns {Uint8Array} The derived key.
 */
export function argon2i(
  password: Uint8Array,
  salt: Uint8Array,
  parameters: Readonly<Argon2Parameters>,
): Uint8Array {
  return argon2(ARGON2I, password, salt, parameters);
}

/**
 * Derives a key with Argon2d, whose memory reads follow the data.
 *
 * @param password - The password.
 * @param salt - The salt, at least 8 bytes.
 * @param parameters - Memory in KiB, iterations, parallelism, key length, and an optional secret
 * and associated data.
 * @returns {Uint8Array} The derived key.
 */
export function argon2d(
  password: Uint8Array,
  salt: Uint8Array,
  parameters: Readonly<Argon2Parameters>,
): Uint8Array {
  return argon2(ARGON2D, password, salt, parameters);
}
