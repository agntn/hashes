import {
  ENCODING_OPTION,
  assertOneRound,
  encodeDigest,
  guarded,
  isInputList,
  outputEncoding,
  toBytes,
} from "./digest.ts";
import { Hash, type HashAbout } from "./hash.ts";
import type { AlgorithmInfo, HashInput, HashOption, HashOptions, HashResult } from "./types.ts";

/** A derived key, and what a caller needs to derive it again: the salt it drew, its costs. */
export interface Derivation {
  /** The raw derived bytes. */
  digest: Uint8Array;
  /** Options the result reports besides its encoding. */
  reported: Record<string, unknown>;
}

/** Base class for a key derivation function, which takes neither an HMAC key nor rounds. */
export abstract class Kdf<Options extends HashOptions = HashOptions> extends Hash {
  /** Label, description, family, category and security note. */
  protected abstract readonly about: HashAbout;
  /** Options besides `encoding`: the salt, the costs, the length. */
  protected readonly options: readonly HashOption[] = [];
  /** Finishes the error that refuses `rounds`, after the key. */
  protected readonly roundsNote: string = "sets its cost with its own parameters";

  /**
   * Derives the key.
   *
   * @param bytes - The input's bytes.
   * @param options - The caller's options.
   * @returns {Derivation} The key and the options it reports.
   */
  protected abstract derive(bytes: Uint8Array, options?: Readonly<Options>): Derivation;

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
   * Derives a key from the input.
   *
   * @param input - Text or bytes, or a list of them.
   * @param options - Encoding and the algorithm's own options.
   * @returns {HashResult | HashResult[]} The derived key, one per input for a list.
   */
  hash(input: HashInput, options?: Readonly<Options>): HashResult;
  hash(inputs: readonly HashInput[], options?: Readonly<Options>): HashResult[];
  hash(
    input: HashInput | readonly HashInput[],
    options?: Readonly<Options>,
  ): HashResult | HashResult[] {
    if (isInputList(input)) return input.map((one) => this.hash(one, options));
    return guarded(this.key, () => {
      if (options?.key !== undefined) throw new Error(`${this.key} has no HMAC mode`);
      assertOneRound(options, `${this.key} ${this.roundsNote}`);
      const encoding = outputEncoding(options);
      const { digest, reported } = this.derive(toBytes(input), options);
      return encodeDigest(digest, this.key, "hash", encoding, reported);
    });
  }
}
