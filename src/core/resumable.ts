/**
 * A hasher that writes its own padding and resumes from its digest, for length extension on a
 * padding `MerkleDamgard` doesn't write, such as Tiger's 0x01.
 */
import { Hasher } from "./hasher.ts";

/** A hasher whose digest is its whole state, padded its own way. */
export abstract class ResumableHasher extends Hasher {
  /**
   * The padding the hash appends after `length` bytes.
   *
   * @param length - Bytes hashed before the padding.
   * @returns {Uint8Array} The padding, ending on a block boundary.
   */
  abstract padding(length: number): Uint8Array;

  /**
   * Picks up from a digest as if `length` bytes, padding included, had been hashed into it.
   *
   * @param digest - A digest that is the whole state.
   * @param length - Bytes hashed with the padding, a multiple of the block length.
   * @returns {this} The same hasher, ready for `update`.
   */
  abstract resume(digest: Uint8Array, length: number): this;
}
