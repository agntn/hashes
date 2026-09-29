import { ENCODING_OPTION, KEY_OPTION } from "./digest.ts";
import { FixedHash } from "./fixed-hash.ts";
import type { Hasher } from "./hasher.ts";
import { hmac } from "./hmac.ts";
import type { AlgorithmInfo } from "./types.ts";

/** Base class for a fixed-length digest built from a `Hasher`, with HMAC over its blocks. */
export abstract class BlockHash extends FixedHash {
  /**
   * Creates the hasher that computes the digest, for input that arrives in pieces.
   *
   * @returns {Hasher} A hasher with nothing absorbed.
   */
  abstract hasher(): Hasher;

  /**
   * Hashes the input in one pass.
   *
   * @param bytes - The input's bytes.
   * @returns {Uint8Array} The digest.
   */
  protected digest(bytes: Uint8Array): Uint8Array {
    return this.hasher().update(bytes).digest();
  }

  /**
   * Computes HMAC with this hash.
   *
   * @param key - The HMAC key.
   * @param bytes - The input's bytes.
   * @returns {Uint8Array} The tag.
   */
  protected override hmac(key: Uint8Array, bytes: Uint8Array): Uint8Array {
    return hmac(() => this.hasher(), key, bytes);
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
      options: [ENCODING_OPTION, KEY_OPTION, ...this.options],
    };
  }
}
