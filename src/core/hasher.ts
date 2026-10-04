/**
 * Incremental hashing: the state HMAC, PBKDF2 and scrypt keep between blocks. An `Hash` class
 * hashes a whole input at once; a `Hasher` takes it in pieces, which is what lets PBKDF2 key the
 * HMAC state once and copy it on every iteration instead of hashing the padded key again.
 */
import { HashError, InvalidOptionError } from "./errors.ts";

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

/** Bytes of each pool the block buffers come from: 64 SHA-512 blocks. */
const POOL_BYTES = 8192;

/** The pool block buffers come from now. */
let pool: ArrayBuffer | undefined;
/** Bytes of it handed out, full at first so the first call makes one. */
let pooled = POOL_BYTES;

/**
 * Cuts a block buffer from a shared pool: a typed array with its own buffer costs about 900 ns.
 *
 * @param length - Bytes, a multiple of 8 up to 8192.
 * @returns {Uint8Array} Zeroed bytes no other hasher holds.
 */
export function poolBytes(length: number): Uint8Array {
  if (pooled + length > POOL_BYTES) {
    pool = new ArrayBuffer(POOL_BYTES);
    pooled = 0;
  }
  pooled += length;
  return new Uint8Array(pool!, pooled - length, length);
}

/**
 * Throws unless the value is bytes. A string or a plain array would otherwise hash to a digest of
 * something else without a word.
 *
 * @param value - What the caller passed.
 * @param name - The argument's name, for the message.
 */
export function assertBytes(value: unknown, name: string): asserts value is Uint8Array {
  if (!(value instanceof Uint8Array)) {
    throw new HashError(
      `${name} must be a Uint8Array, not ${value === null ? "null" : typeof value}`,
    );
  }
}

/**
 * Calls a hasher factory and throws unless it gave a hasher. Plain JavaScript can pass the
 * registry's `create(name)`, whose `Hash` would otherwise fail deep inside the KDF.
 *
 * @param create - What the caller passed as the factory.
 * @returns {Hasher} A fresh hasher.
 */
export function createHasher(create: () => Hasher): Hasher {
  if (typeof create !== "function") {
    throw new InvalidOptionError(
      "create",
      nameOf(create),
      "must be a function that returns a Hasher",
    );
  }
  const hasher: unknown = create();
  if (!isHasher(hasher)) {
    throw new InvalidOptionError(
      "create",
      nameOf(hasher),
      "must return a Hasher, such as new Sha256Hasher()",
    );
  }
  return hasher;
}

/**
 * Tells a hasher by its methods and lengths, so one from another copy of this package still
 * passes. A zero output length would keep `evpBytesToKey` looping forever.
 *
 * @param value - What the factory returned.
 * @returns {boolean} Whether it has every method and a positive length of each kind.
 */
function isHasher(value: unknown): value is Hasher {
  if (typeof value !== "object" || value === null) return false;
  const fields = value as Partial<Record<string, unknown>>;
  return (
    ["update", "digestInto", "digest", "load"].every(
      (name) => typeof fields[name] === "function",
    ) &&
    [fields.blockLength, fields.outputLength].every(
      (length) => typeof length === "number" && Number.isSafeInteger(length) && length > 0,
    )
  );
}

/**
 * Names a value for an error message: a function or an object by its name, anything else as it is.
 *
 * @param value - The value.
 * @returns {string} Its name.
 */
function nameOf(value: unknown): string {
  if (typeof value === "function") return value.name || "function";
  if (typeof value !== "object" || value === null) return String(value);
  const name: unknown = (value as { constructor?: { name?: unknown } }).constructor?.name;
  return typeof name === "string" && name !== "" ? name : "object";
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
 * Writes a byte count as the 64-bit bit length that ends the padding, in the last 8 bytes before
 * `end`. A wider length field only ever holds zeros above them here.
 *
 * @param view - The block or padding being written.
 * @param end - Where the length field ends.
 * @param length - Bytes hashed.
 * @param littleEndian - Byte order of the field.
 */
export function writeBitLength(
  view: DataView,
  end: number,
  length: number,
  littleEndian: boolean,
): void {
  const high = Math.floor(length / 0x2000_0000);
  const low = (length % 0x2000_0000) * 8;
  view.setUint32(end - 8, littleEndian ? low : high, littleEndian);
  view.setUint32(end - 4, littleEndian ? high : low, littleEndian);
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
  readonly littleEndian: boolean;
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
    this.buffer = poolBytes(blockLength);
    this.bufferView = viewOf(this.buffer);
  }

  /**
   * Compresses one block into the state.
   *
   * @param view - A view holding the block.
   * @param offset - Where the block starts in the view.
   */
  protected abstract compress(view: DataView, offset: number): void;

  /**
   * Copies short input byte by byte: a subarray or a view over it costs more than the copy.
   *
   * @param data - The next bytes.
   * @returns {this} The same hasher.
   */
  update(data: Uint8Array): this {
    assertBytes(data, "data");
    const { buffer, blockLength: block } = this;
    const length = data.length;
    let position = this.position;
    let offset = 0;
    this.length += length;
    if (position > 0 || length <= block) {
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
    while (position < block - 8) buffer[position++] = 0;
    this.position = position;
    writeBitLength(view, block, length, littleEndian);
    this.compress(view, 0);
    wordsToBytes(state, out, this.outputLength, littleEndian);
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
   * Picks up from a digest as if `length` bytes, padding included, had been hashed into it.
   *
   * @param digest - A digest of `stateLength` bytes.
   * @param length - Bytes hashed with the padding, a multiple of the block length.
   * @returns {this} The same hasher, ready for `update`.
   */
  resume(digest: Uint8Array, length: number): this {
    assertBytes(digest, "digest");
    const { state, littleEndian } = this;
    if (digest.length !== state.length * 4 || !(length >= 0 && length % this.blockLength === 0)) {
      throw new HashError(
        `resume takes a ${state.length * 4}-byte digest and a multiple of ${this.blockLength} bytes`,
      );
    }
    const view = viewOf(digest);
    for (let i = 0; i < state.length; i++) state[i] = view.getInt32(i * 4, littleEndian);
    this.position = 0;
    this.length = length;
    return this;
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
    this.block = poolBytes(blockLength);
  }

  /**
   * Compresses the block buffer into the state.
   *
   * @param counter - Bytes hashed through this block.
   * @param last - Whether this is the final block.
   */
  protected abstract compress(counter: number, last: boolean): void;

  update(data: Uint8Array): this {
    assertBytes(data, "data");
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
