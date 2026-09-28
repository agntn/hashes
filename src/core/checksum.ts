import { ENCODING_OPTION, encodeDigest, guarded, toBytes } from "./digest.ts";
import { Hash, type HashAbout } from "./hash.ts";
import type { AlgorithmInfo, HashInput, HashOption, HashOptions, HashResult } from "./types.ts";

/** Base class for a fixed-length digest this package computes itself, such as a checksum. */
export abstract class ChecksumHash<Options extends HashOptions = HashOptions> extends Hash {
  /** Label, description, family, digest length and security note. */
  protected abstract readonly about: HashAbout;
  /** Options besides `encoding`. */
  protected readonly options: readonly HashOption[] = [];

  /**
   * Computes the raw digest.
   *
   * @param bytes - The input's bytes.
   * @param options - The caller's options.
   * @returns {Uint8Array} The digest.
   */
  protected abstract digest(bytes: Uint8Array, options?: Readonly<Options>): Uint8Array;

  /**
   * Lists the options the result reports besides its encoding.
   *
   * @param _options - The caller's options.
   * @returns {Record<string, unknown>} Nothing by default.
   */
  protected reported(_options?: Readonly<Options>): Record<string, unknown> {
    return {};
  }

  /**
   * Describes the algorithm.
   *
   * @returns {AlgorithmInfo} Its metadata.
   */
  info(): AlgorithmInfo {
    return {
      name: this.key,
      ...this.about,
      hmac: false,
      options: [ENCODING_OPTION, ...this.options],
    };
  }

  /**
   * Hashes the input.
   *
   * @param input - Text or bytes.
   * @param options - Encoding and the algorithm's own options.
   * @returns {HashResult} The digest.
   */
  hash(input: HashInput, options?: Readonly<Options>): HashResult {
    return guarded(this.key, () => {
      if (options?.key !== undefined) throw new Error(`${this.key} has no HMAC mode`);
      return encodeDigest(
        this.digest(toBytes(input), options),
        this.key,
        "hash",
        options?.encoding ?? "hex",
        this.reported(options),
      );
    });
  }
}
