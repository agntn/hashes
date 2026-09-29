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
   * Finishes and returns the digest.
   *
   * @returns {Uint8Array} `outputLength` bytes.
   */
  digest(): Uint8Array {
    const out = new Uint8Array(this.outputLength);
    this.digestInto(out);
    return out;
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
 * Writes the leading bytes of a state held as 32-bit words.
 *
 * @param words - The state.
 * @param out - Receives `length` bytes from index 0.
 * @param length - Bytes to write.
 * @param littleEndian - Byte order of each word.
 */
export function wordsToBytes(
  words: Int32Array,
  out: Uint8Array,
  length: number,
  littleEndian: boolean,
): void {
  if (littleEndian) {
    for (let i = 0; i < length; i++) out[i] = words[i >> 2]! >>> ((i & 3) << 3);
  } else {
    for (let i = 0; i < length; i++) out[i] = words[i >> 2]! >>> (24 - ((i & 3) << 3));
  }
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
   * @param littleEndian - Byte order of the words, the length and the digest.
   */
  constructor(blockLength: number, outputLength: number, littleEndian: boolean) {
    super();
    this.blockLength = blockLength;
    this.outputLength = outputLength;
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
    // The bit length takes the last eighth of the block: 8 bytes, or 16 for SHA-512.
    if (position > block - (block >> 3)) {
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
    wordsToBytes(state, out, this.outputLength, littleEndian);
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

/**
 * BLAKE2 hashing (RFC 7693): blocks go to `compress` with the count of bytes hashed through them.
 * The buffer keeps the last block, even a full one, until the digest can flag it as final.
 */
export abstract class Blake2 extends Hasher {
  /** Chaining value as little-endian 32-bit words. */
  protected abstract readonly state: Int32Array;
  readonly blockLength: number;
  readonly outputLength: number;
  /** The block `compress` reads. */
  protected readonly block: Uint8Array;
  /** Bytes in the block buffer. */
  private position = 0;
  /** Bytes compressed so far. */
  private counter = 0;

  /**
   * @param blockLength - Bytes per block: 128 for BLAKE2b, 64 for BLAKE2s.
   * @param outputLength - Digest bytes, a prefix of the state.
   */
  constructor(blockLength: number, outputLength: number) {
    super();
    this.blockLength = blockLength;
    this.outputLength = outputLength;
    this.block = new Uint8Array(blockLength);
  }

  /**
   * Compresses the block buffer into the state.
   *
   * @param counter - Bytes hashed through this block.
   * @param last - Whether this is the final block.
   */
  protected abstract compress(counter: number, last: boolean): void;

  update(data: Uint8Array): this {
    const { block, blockLength } = this;
    let position = this.position;
    for (let offset = 0; offset < data.length;) {
      if (position === blockLength) {
        this.counter += blockLength;
        this.compress(this.counter, false);
        position = 0;
      }
      while (offset < data.length && position < blockLength) block[position++] = data[offset++]!;
    }
    this.position = position;
    return this;
  }

  digestInto(out: Uint8Array): void {
    this.block.fill(0, this.position);
    this.compress(this.counter + this.position, true);
    wordsToBytes(this.state, out, this.outputLength, true);
  }

  load(source: this): this {
    this.state.set(source.state);
    this.block.set(source.block);
    this.position = source.position;
    this.counter = source.counter;
    return this;
  }
}
