import { hmac } from "@noble/hashes/hmac.js";
import type { CHash } from "@noble/hashes/utils.js";
import { ENCODING_OPTION, encodeDigest, guarded, toBytes } from "./digest.ts";
import { Hash } from "./hash.ts";
import type { AlgorithmInfo, HashInput, HashOption, HashOptions, HashResult } from "./types.ts";

/** What an algorithm tells about itself besides its name, options and HMAC support. */
export type HashAbout = Pick<
  AlgorithmInfo,
  "label" | "description" | "family" | "digestLength" | "securityNote"
>;

const KEY_OPTION: HashOption = {
  name: "key",
  type: "string",
  required: false,
  description: "HMAC key; enables HMAC mode",
};

/** Base class for an algorithm over a @noble/hashes function, with HMAC through `@noble/hashes/hmac`. */
export abstract class NobleHash extends Hash {
  /** The noble hash, such as `sha256` or `blake2b`. */
  protected abstract readonly hashFn: CHash;
  /** Label, description, family, digest length and security note. */
  protected abstract readonly about: HashAbout;
  /** Whether HMAC mode is offered. */
  protected readonly hmac: boolean = true;

  /**
   * Describes the algorithm.
   *
   * @returns {AlgorithmInfo} Its metadata.
   */
  info(): AlgorithmInfo {
    return {
      name: this.key,
      ...this.about,
      hmac: this.hmac,
      options: this.hmac ? [ENCODING_OPTION, KEY_OPTION] : [ENCODING_OPTION],
    };
  }

  /**
   * Hashes the input, or computes its HMAC when a key is given.
   *
   * @param input - Text or bytes.
   * @param options - Encoding and HMAC key.
   * @returns {HashResult} The digest.
   */
  hash(input: HashInput, options?: HashOptions): HashResult {
    return guarded(this.key, () => {
      const data = toBytes(input);
      const encoding = options?.encoding ?? "hex";
      if (options?.key === undefined) {
        return encodeDigest(this.hashFn(data), this.key, "hash", encoding);
      }
      if (!this.hmac) throw new Error(`${this.key} has no HMAC mode`);
      const raw = hmac(this.hashFn, toBytes(options.key), data);
      return encodeDigest(raw, this.key, "hmac", encoding, { hmac: true });
    });
  }
}
