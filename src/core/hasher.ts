/**
 * Incremental hashing: the state HMAC, PBKDF2 and scrypt keep between blocks. An `Hash` class
 * hashes a whole input at once; a `Hasher` takes it in pieces, which is what lets PBKDF2 key the
 * HMAC state once and copy it on every iteration instead of hashing the padded key again.
 */

/** Incremental state of a hash that works in blocks. */
export abstract class Hasher {
  /** Bytes per block, which is also the HMAC key block. */
  abstract readonly blockLength: number;
  /** Digest length in bytes. */
  abstract readonly outputLength: number;

  /**
   * Absorbs more input.
   *
   * @param data - The next bytes.
   * @returns {this} The same hasher.
   */
  abstract update(data: Uint8Array): this;

  /**
   * Pads, finishes and writes the digest. The hasher is spent afterwards until `load` resets it.
   *
   * @param out - Receives `outputLength` bytes from index 0.
   */
  abstract digestInto(out: Uint8Array): void;

  /**
   * Takes over the whole state of a hasher of the same class and output length.
   *
   * @param source - The hasher to copy.
   * @returns {this} The same hasher.
   */
  abstract load(source: this): this;

  /**
   * Creates a fresh hasher of the same class and output length.
   *
   * @returns {this} A hasher with nothing absorbed.
   */
  abstract fresh(): this;

  /**
   * Finishes and returns the digest.
   *
   * @returns {Uint8Array} `outputLength` bytes.
   */
  digest(): Uint8Array {
    const out = new Uint8Array(this.outputLength);
    this.digestInto(out);
    return out;
  }

  /**
   * Copies the hasher, state and all.
   *
   * @returns {this} An independent hasher at the same point.
   */
  clone(): this {
    return this.fresh().load(this);
  }
}

/**
 * A view over the input's bytes that reads words in either byte order.
 *
 * @param data - The bytes.
 * @returns {DataView} A view over exactly those bytes.
 */
export function viewOf(data: Uint8Array): DataView {
  return new DataView(data.buffer, data.byteOffset, data.byteLength);
}

/**
 * Merkle-Damgard hashing: MD5, SHA-1, SHA-2 and RIPEMD-160. Blocks go to `compress`, the last one
 * padded with 0x80, zeros and the message length in bits; the digest is the state's words.
 */
export abstract class MerkleDamgard extends Hasher {
  /** Chaining value as 32-bit words; for SHA-512 each 64-bit word is a high then a low half. */
  protected abstract readonly state: Int32Array;
  readonly blockLength: number;
  readonly outputLength: number;
  /** Bytes the padding gives the bit length. */
  private readonly lengthField: number;
  /** Byte order of the words, the length and the digest. */
  private readonly littleEndian: boolean;
  /** The partial block not compressed yet. */
  private readonly buffer: Uint8Array;
  private readonly bufferView: DataView;
  /** Bytes waiting in the buffer. */
  private position = 0;
  /** Bytes absorbed so far. */
  private length = 0;

  /**
   * @param blockLength - Bytes per block: 64, or 128 for SHA-512.
   * @param outputLength - Digest bytes, a prefix of the state.
   * @param lengthField - Bytes the padding gives the bit length: 8, or 16 for SHA-512.
   * @param littleEndian - Byte order of the words, the length and the digest.
   */
  constructor(
    blockLength: number,
    outputLength: number,
    lengthField: number,
    littleEndian: boolean,
  ) {
    super();
    this.blockLength = blockLength;
    this.outputLength = outputLength;
    this.lengthField = lengthField;
    this.littleEndian = littleEndian;
    this.buffer = new Uint8Array(blockLength);
    this.bufferView = new DataView(this.buffer.buffer);
  }

  /**
   * Compresses one block into the state.
   *
   * @param view - A view holding the block.
   * @param offset - Where the block starts in the view.
   */
  protected abstract compress(view: DataView, offset: number): void;

  update(data: Uint8Array): this {
    const { buffer, blockLength: block } = this;
    const length = data.length;
    let position = this.position;
    let offset = 0;
    this.length += length;
    // Short pieces go byte by byte: a subarray per call costs more than copying a block here.
    if (position > 0) {
      while (offset < length && position < block) buffer[position++] = data[offset++]!;
      if (position < block) {
        this.position = position;
        return this;
      }
      this.compress(this.bufferView, 0);
      position = 0;
    }
    if (length - offset >= block) {
      const view = viewOf(data);
      for (; length - offset >= block; offset += block) this.compress(view, offset);
    }
    while (offset < length) buffer[position++] = data[offset++]!;
    this.position = position;
    return this;
  }

  digestInto(out: Uint8Array): void {
    const { buffer, bufferView: view, blockLength: block, littleEndian, state } = this;
    const length = this.length;
    let position = this.position;
    buffer[position++] = 0x80;
    if (position > block - this.lengthField) {
      while (position < block) buffer[position++] = 0;
      this.compress(view, 0);
      position = 0;
    }
    // A length field wider than 8 bytes only ever holds zeros above them here.
    while (position < block - 8) buffer[position++] = 0;
    this.position = position;
    const high = Math.floor(length / 0x2000_0000);
    const low = (length * 8) >>> 0;
    view.setUint32(block - 8, littleEndian ? low : high, littleEndian);
    view.setUint32(block - 4, littleEndian ? high : low, littleEndian);
    this.compress(view, 0);
    const outputLength = this.outputLength;
    if (littleEndian) {
      for (let i = 0; i < outputLength; i++) out[i] = state[i >> 2]! >>> ((i & 3) << 3);
    } else {
      for (let i = 0; i < outputLength; i++) out[i] = state[i >> 2]! >>> (24 - ((i & 3) << 3));
    }
  }

  load(source: this): this {
    const { buffer, position } = source;
    this.state.set(source.state);
    for (let i = 0; i < position; i++) this.buffer[i] = buffer[i]!;
    this.position = position;
    this.length = source.length;
    return this;
  }
}
