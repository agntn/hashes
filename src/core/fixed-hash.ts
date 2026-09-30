import {
  CHAIN_OPTION,
  ENCODING_OPTION,
  ROUNDS_OPTION,
  assertOneRound,
  encodeDigest,
  guarded,
  roundOptions,
  toBytes,
} from "./digest.ts";
import { Hash, type HashAbout } from "./hash.ts";
import type { AlgorithmInfo, HashInput, HashOption, HashOptions, HashResult } from "./types.ts";

/** The options every fixed-length digest takes: how many rounds, and what each next one hashes. */
export const ROUND_OPTIONS: readonly HashOption[] = [ROUNDS_OPTION, CHAIN_OPTION];

/** Base class for a fixed-length digest, with no HMAC mode unless a subclass adds one. */
export abstract class FixedHash<Options extends HashOptions = HashOptions> extends Hash {
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
   * Computes the HMAC of the input. A fixed hash has none; `BlockHash` adds it.
   *
   * @param _key - The HMAC key.
   * @param _bytes - The input's bytes.
   * @returns {Uint8Array} The tag.
   */
  protected hmac(_key: Uint8Array, _bytes: Uint8Array): Uint8Array {
    throw new Error(`${this.key} has no HMAC mode`);
  }

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
      options: [ENCODING_OPTION, ...this.options, ...ROUND_OPTIONS],
    };
  }

  /**
   * Hashes the input `rounds` times, or computes its HMAC when a key is given.
   *
   * @param input - Text or bytes.
   * @param options - Encoding, HMAC key, rounds and the algorithm's own options.
   * @returns {HashResult} The digest.
   */
  hash(input: HashInput, options?: Readonly<Options>): HashResult {
    return guarded(this.key, () => {
      const encoding = options?.encoding ?? "hex";
      const { rounds, chain } = roundOptions(options);
      if (options?.key !== undefined) {
        assertOneRound(options, "HMAC runs one round");
        const tag = this.hmac(toBytes(options.key), toBytes(input));
        return encodeDigest(tag, this.key, "hmac", encoding, { hmac: true });
      }
      let digest = this.digest(toBytes(input), options);
      for (let round = 1; round < rounds; round++) {
        digest = this.digest(chain === "hex" ? toBytes(digest.toHex()) : digest, options);
      }
      const reported = this.reported(options);
      return encodeDigest(
        digest,
        this.key,
        "hash",
        encoding,
        rounds > 1 ? { ...reported, rounds, chain } : reported,
      );
    });
  }
}
