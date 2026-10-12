/**
 * A hasher that writes its own padding and resumes from its digest, for length extension on a
 * padding `MerkleDamgard` doesn't write, such as Tiger's 0x01 or Whirlpool's 256-bit length. It
 * buffers 64-byte blocks itself, so `MerkleDamgard` and the byte function bundles stay as they are.
 */
import { HashError } from "./errors.ts";
import { Hasher, assertBytes, viewOf, wordsToBytes } from "./hasher.ts";

/** Bytes per block. */
const BLOCK = 64;

/**
 * Writes the bit length before `end`, with no `DataView` to move a buffer off-heap.
 *
 * @param out - The block or padding being written.
 * @param end - Where the length field ends.
 * @param length - Bytes hashed.
 * @param littleEndian - Byte order of the field.
 */
function writeLength(out: Uint8Array, end: number, length: number, littleEndian: boolean): void {
  const low = (length % 0x2000_0000) * 8;
  const high = Math.floor(length / 0x2000_0000);
  for (let i = 0; i < 4; i++) {
    const shift = littleEndian ? 8 * i : 24 - 8 * i;
    out[end - 8 + i] = (littleEndian ? low : high) >>> shift;
    out[end - 4 + i] = (littleEndian ? high : low) >>> shift;
  }
}

/** A hasher whose digest is its whole state, padded with a marker, zeros and the bit length. */
export abstract class ResumableHasher extends Hasher {
  readonly blockLength = BLOCK;
  /** The chaining value, which the digest prints whole. */
  protected abstract readonly state: Int32Array;
  /** Byte order of the state words and the length. */
  protected abstract readonly littleEndian: boolean;
  /** The byte the padding opens with. */
  protected abstract readonly marker: number;
  /** Bytes the padding gives the bit length, zeros above its low 8. */
  protected abstract readonly lengthBytes: number;
  /** The partial block not compressed yet. */
  private readonly buffer = new Uint8Array(BLOCK);
  /** Bytes waiting in the buffer. */
  private position = 0;
  /** Bytes absorbed so far. */
  private length = 0;

  /**
   * Compresses one block into the state.
   *
   * @param block - Bytes holding the block.
   * @param offset - Where the block starts.
   */
  protected abstract compress(block: Uint8Array, offset: number): void;

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
      this.compress(buffer, 0);
      position = 0;
    }
    for (; length - offset >= BLOCK; offset += BLOCK) this.compress(data, offset);
    while (offset < length) buffer[position++] = data[offset++]!;
    this.position = position;
    return this;
  }

  digestInto(out: Uint8Array): void {
    const { buffer } = this;
    let position = this.position;
    buffer[position++] = this.marker;
    if (position > BLOCK - this.lengthBytes) {
      buffer.fill(0, position);
      this.compress(buffer, 0);
      position = 0;
    }
    buffer.fill(0, position, BLOCK - 8);
    writeLength(buffer, BLOCK, this.length, this.littleEndian);
    this.compress(buffer, 0);
    wordsToBytes(this.state, out, this.outputLength, this.littleEndian);
  }

  /**
   * The padding the hash appends after `length` bytes.
   *
   * @param length - Bytes hashed before the padding.
   * @returns {Uint8Array} The padding, ending on a block boundary.
   */
  padding(length: number): Uint8Array {
    const least = 1 + this.lengthBytes;
    const size = least + ((BLOCK - ((length + least) % BLOCK)) % BLOCK);
    const out = new Uint8Array(size);
    out[0] = this.marker;
    writeLength(out, size, length, this.littleEndian);
    return out;
  }

  /**
   * Picks up from a digest as if `length` bytes, padding included, had been hashed into it.
   *
   * @param digest - A digest that is the whole state.
   * @param length - Bytes hashed with the padding, a multiple of the block length.
   * @returns {this} The same hasher, ready for `update`.
   */
  resume(digest: Uint8Array, length: number): this {
    assertBytes(digest, "digest");
    const { state, littleEndian } = this;
    if (digest.length !== this.outputLength || !(length >= 0 && length % BLOCK === 0)) {
      throw new HashError(
        `resume takes a ${this.outputLength}-byte digest and a multiple of ${BLOCK} bytes`,
      );
    }
    const view = viewOf(digest);
    for (let i = 0; i < state.length; i++) state[i] = view.getInt32(i * 4, littleEndian);
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
}
