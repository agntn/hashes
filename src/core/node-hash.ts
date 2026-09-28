import { createHash, createHmac } from "node:crypto";
import { ENCODING_OPTION, encodeDigest, guarded, toBytes } from "./digest.ts";
import { Hash, type HashAbout } from "./hash.ts";
import type { AlgorithmInfo, HashInput, HashOption, HashOptions, HashResult } from "./types.ts";

const KEY_OPTION: HashOption = {
  name: "key",
  type: "string",
  required: false,
  description: "HMAC key; enables HMAC mode",
};

/** Base class for an algorithm Node computes natively through OpenSSL, with HMAC through `createHmac`. */
export abstract class NodeHash extends Hash {
  /** The OpenSSL digest name `node:crypto` knows, such as `sha256` or `blake2b512`. */
  protected abstract readonly algorithm: string;
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
        return encodeDigest(
          createHash(this.algorithm).update(data).digest(),
          this.key,
          "hash",
          encoding,
        );
      }
      if (!this.hmac) throw new Error(`${this.key} has no HMAC mode`);
      const raw = createHmac(this.algorithm, toBytes(options.key)).update(data).digest();
      return encodeDigest(raw, this.key, "hmac", encoding, { hmac: true });
    });
  }
}
