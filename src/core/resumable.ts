/**
 * A hasher that writes its own padding and resumes from its digest, for length extension on a
 * padding `MerkleDamgard` doesn't write, such as Tiger's 0x01, Whirlpool's 256-bit length or
 * HAVAL's fields before the length. It buffers its blocks itself, so `MerkleDamgard` and the byte
 * function bundles stay as they are.
 */
import { HashError } from "./errors.ts";
import { Hasher, assertBytes, viewOf, wordsToBytes } from "./hasher.ts";

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

/** A hasher padded with a marker, zeros, its own fields and the bit length. */
export abstract class ResumableHasher extends Hasher {
  readonly blockLength: number;
  /** The chaining value. Only a digest that prints all of it lets the hash resume. */
  protected abstract readonly state: Int32Array;
  /** Byte order of the state words and the length. */
  protected abstract readonly littleEndian: boolean;
  /** The byte the padding opens with. */
  protected abstract readonly marker: number;
  /** Bytes the padding ends with: the bit length, zeros above its low 8, and any fields. */
  protected abstract readonly lengthBytes: number;
  /** The partial block not compressed yet. */
  private readonly buffer: Uint8Array;
  /** Bytes waiting in the buffer. */
  private position = 0;
  /** Bytes absorbed so far. */
  private length = 0;

  /**
   * @param blockLength - Bytes per block. Default: 64, as Tiger and Whirlpool.
   */
  constructor(blockLength = 64) {
    super();
    this.blockLength = blockLength;
    this.buffer = new Uint8Array(blockLength);
  }

  /**
   * Compresses one block into the state.
   *
   * @param block - Bytes holding the block.
   * @param offset - Where the block starts.
   */
  protected abstract compress(block: Uint8Array, offset: number): void;

  /**
   * Writes the fields the padding carries before the bit length. Tiger and Whirlpool have none.
   * A hook rather than a byte array of fields: allocating one per hasher cost HAVAL about 5%.
   *
   * @param _out - The block or padding being written.
   * @param _at - Where the bit length starts.
   */
  protected writeFields(_out: Uint8Array, _at: number): void {}

  /** Runs after the last block, before the state goes out. HAVAL folds its words down here. */
  protected finish(): void {}

  update(data: Uint8Array): this {
    assertBytes(data, "data");
    const { buffer, blockLength: block } = this;
    const length = data.length;
    let position = this.position;
    let offset = 0;
    this.length += length;
    if (position > 0) {
      while (offset < length && position < block) buffer[position++] = data[offset++]!;
      if (position < block) {
        this.position = position;
        return this;
      }
      this.compress(buffer, 0);
      position = 0;
    }
    for (; length - offset >= block; offset += block) this.compress(data, offset);
    while (offset < length) buffer[position++] = data[offset++]!;
    this.position = position;
    return this;
  }

  digestInto(out: Uint8Array): void {
    const { buffer, blockLength: block } = this;
    let position = this.position;
    buffer[position++] = this.marker;
    if (position > block - this.lengthBytes) {
      buffer.fill(0, position);
      this.compress(buffer, 0);
      position = 0;
    }
    buffer.fill(0, position, block - 8);
    this.writeTrailer(buffer, block, this.length);
    this.compress(buffer, 0);
    this.finish();
    wordsToBytes(this.state, out, this.outputLength, this.littleEndian);
  }

  /**
   * Bytes of the chaining value. Only a digest this long lets the hash resume from it.
   *
   * @returns {number} The state's size in bytes.
   */
  get stateLength(): number {
    return this.state.length * 4;
  }

  /**
   * The padding the hash appends after `length` bytes.
   *
   * @param length - Bytes hashed before the padding.
   * @returns {Uint8Array} The padding, ending on a block boundary.
   */
  padding(length: number): Uint8Array {
    const block = this.blockLength;
    const least = 1 + this.lengthBytes;
    const size = least + ((block - ((length + least) % block)) % block);
    const out = new Uint8Array(size);
    out[0] = this.marker;
    this.writeTrailer(out, size, length);
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
    const { state, littleEndian, stateLength, blockLength: block } = this;
    if (this.outputLength !== stateLength) {
      throw new HashError(`a ${this.outputLength}-byte digest leaves part of the state out`);
    }
    if (digest.length !== stateLength || !(length >= 0 && length % block === 0)) {
      throw new HashError(
        `resume takes a ${stateLength}-byte digest and a multiple of ${block} bytes`,
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

  /**
   * Writes the fields and the bit length that end the padding.
   *
   * @param out - The block or padding being written.
   * @param end - Where the padding ends.
   * @param length - Bytes hashed before the padding.
   */
  private writeTrailer(out: Uint8Array, end: number, length: number): void {
    this.writeFields(out, end - 8);
    writeLength(out, end, length, this.littleEndian);
  }
}
