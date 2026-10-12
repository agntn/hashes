/**
 * MD2 (RFC 1319): 16-byte blocks stirred through a 48-byte state, plus a running checksum hashed
 * as one last block. Both run every byte through a permutation drawn from the digits of π.
 */
import { Hasher, assertBytes } from "./hasher.ts";
import { machinPi } from "./pi.ts";

/** Bytes per block, and of the digest. */
const BLOCK = 16;

let piSubstitution: Uint8Array | undefined;

/**
 * Computes π's leading decimal digits.
 *
 * @param count - Digits after the leading 3.
 * @returns {string} `"314159…"`, `count + 1` digits.
 */
function piDigits(count: number): string {
  const guard = 10n ** 10n;
  return String(machinPi(10n ** BigInt(count) * guard) / guard);
}

/**
 * Rebuilds RFC 1319's permutation from π once, instead of shipping 256 numbers. Each swap of the
 * shuffle reads one to three digits and skips a biased pick. 722 digits in all, the 3 included.
 *
 * @returns {Uint8Array} The 256-byte table, 41 first.
 */
function substitution(): Uint8Array {
  if (piSubstitution) return piSubstitution;
  const digits = piDigits(722);
  const table = Uint8Array.from({ length: 256 }, (_, index) => index);
  let next = 0;
  for (let n = 2; n <= 256; n++) {
    const width = n > 100 ? 3 : n > 10 ? 2 : 1;
    const limit = 10 ** width - (10 ** width % n);
    let pick = limit;
    while (pick >= limit) {
      pick = Number(digits.slice(next, next + width));
      next += width;
    }
    const swap = pick % n;
    [table[swap], table[n - 1]] = [table[n - 1]!, table[swap]!];
  }
  piSubstitution = table;
  return table;
}

/** MD2. */
export class Md2Hasher extends Hasher {
  readonly blockLength = BLOCK;
  readonly outputLength = BLOCK;
  /** π's permutation. */
  private readonly table = substitution();
  /** The 48-byte state. Its first 16 bytes are the digest. */
  private readonly state = new Uint8Array(3 * BLOCK);
  /** The checksum of every block so far. */
  private readonly checksum = new Uint8Array(BLOCK);
  /** The partial block not compressed yet. */
  private readonly buffer = new Uint8Array(BLOCK);
  /** Bytes waiting in the buffer. */
  private position = 0;

  update(data: Uint8Array): this {
    assertBytes(data, "data");
    const { buffer } = this;
    const length = data.length;
    let position = this.position;
    let offset = 0;
    if (position > 0) {
      while (offset < length && position < BLOCK) buffer[position++] = data[offset++]!;
      if (position < BLOCK) {
        this.position = position;
        return this;
      }
      this.compress(buffer, 0);
      position = 0;
    }
    for (; length - offset >= BLOCK; offset += BLOCK) this.compress(data, offset);
    while (offset < length) buffer[position++] = data[offset++]!;
    this.position = position;
    return this;
  }

  digestInto(out: Uint8Array): void {
    const { buffer, position, state } = this;
    buffer.fill(BLOCK - position, position);
    this.compress(buffer, 0);
    this.mix(this.checksum, 0);
    for (let i = 0; i < BLOCK; i++) out[i] = state[i]!;
  }

  load(source: this): this {
    this.state.set(source.state);
    this.checksum.set(source.checksum);
    this.buffer.set(source.buffer);
    this.position = source.position;
    return this;
  }

  /**
   * Adds one block to the checksum, then to the state.
   *
   * @param block - Bytes holding the block.
   * @param offset - Where the block starts.
   */
  private compress(block: Uint8Array, offset: number): void {
    const { checksum, table } = this;
    let last = checksum[BLOCK - 1]!;
    for (let j = 0; j < BLOCK; j++) {
      last = checksum[j]! ^ table[block[offset + j]! ^ last]!;
      checksum[j] = last;
    }
    this.mix(block, offset);
  }

  /**
   * Stirs one block into the state: eighteen passes over all 48 bytes.
   *
   * @param block - Bytes holding the block.
   * @param offset - Where the block starts.
   */
  private mix(block: Uint8Array, offset: number): void {
    const { state, table } = this;
    for (let j = 0; j < BLOCK; j++) {
      const byte = block[offset + j]!;
      state[BLOCK + j] = byte;
      state[2 * BLOCK + j] = byte ^ state[j]!;
    }
    let t = 0;
    for (let pass = 0; pass < 18; pass++) {
      for (let k = 0; k < 3 * BLOCK; k++) {
        t = state[k]! ^ table[t]!;
        state[k] = t;
      }
      t = (t + pass) & 0xff;
    }
  }
}
