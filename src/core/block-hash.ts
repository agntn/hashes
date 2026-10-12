import { ENCODING_OPTION, KEY_OPTION } from "./digest.ts";
import { FixedHash, ROUND_OPTIONS } from "./fixed-hash.ts";
import type { Hasher } from "./hasher.ts";
import { hmac } from "./hmac.ts";
import type { AlgorithmInfo, HashOptions } from "./types.ts";

/** Base class for a fixed-length digest built from a `Hasher`, with HMAC over its blocks. */
export abstract class BlockHash<
  Options extends HashOptions = HashOptions,
> extends FixedHash<Options> {
  /**
   * Creates the hasher that computes the digest, for input that arrives in pieces.
   *
   * @param options - The algorithm's own options, such as HAVAL's passes and length.
   * @returns {Hasher} A hasher with nothing absorbed.
   */
  abstract hasher(options?: Readonly<Options>): Hasher;

  /**
   * Hashes the input in one pass.
   *
   * @param bytes - The input's bytes.
   * @param options - The algorithm's own options.
   * @returns {Uint8Array} The digest.
   */
  protected digest(bytes: Uint8Array, options?: Readonly<Options>): Uint8Array {
    return this.hasher(options).update(bytes).digest();
  }

  /**
   * Computes HMAC with this hash.
   *
   * @param key - The HMAC key.
   * @param bytes - The input's bytes.
   * @param options - The algorithm's own options.
   * @returns {Uint8Array} The tag.
   */
  protected override hmac(
    key: Uint8Array,
    bytes: Uint8Array,
    options?: Readonly<Options>,
  ): Uint8Array {
    return hmac(() => this.hasher(options), key, bytes);
  }

  /**
   * Describes the algorithm, HMAC mode included.
   *
   * @returns {AlgorithmInfo} Its metadata.
   */
  override info(): AlgorithmInfo {
    return {
      ...super.info(),
      hmac: true,
      options: [ENCODING_OPTION, KEY_OPTION, ...this.options, ...ROUND_OPTIONS],
    };
  }
}
