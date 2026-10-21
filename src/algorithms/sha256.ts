import { BlockHash } from "../core/block-hash.ts";
import { assertOneRound } from "../core/digest.ts";
import { InvalidOptionError } from "../core/errors.ts";
import type { Hasher } from "../core/hasher.ts";
import { Sha256Hasher, sha256Bits } from "../core/sha2.ts";
import type { HashOptions } from "../core/types.ts";

/** Options SHA-256 takes besides the encoding and the HMAC key. */
export interface Sha256Options extends HashOptions {
  /** Message length in bits, for a message whose last byte is partial. Default: every input bit. */
  bitLength?: number;
}

export class Sha256 extends BlockHash<Sha256Options> {
  static readonly key = "sha256";
  protected readonly about = {
    label: "SHA-256",
    description:
      "SHA-2 family 256-bit hash, widely used for digital signatures, certificates, and integrity checks",
    family: "SHA",
    category: "cryptographic",
    digestLength: 32,
    securityNote: "128-bit collision resistance, 256-bit preimage resistance",
  } as const;
  protected override readonly options = [
    {
      name: "bitLength",
      type: "number",
      required: false,
      description:
        "Message length in bits when the last byte is partial: the message fills each byte from the top bit, the unused bits are zero",
    },
  ] as const;

  /**
   * Creates the hasher, which takes whole bytes, the way HMAC and length extension feed it.
   *
   * @param options - Refused with a bit length.
   * @returns {Hasher} A fresh one.
   */
  hasher(options?: Readonly<Sha256Options>): Hasher {
    if (options?.bitLength !== undefined) {
      throw new InvalidOptionError(
        "bitLength",
        options.bitLength,
        "HMAC and length extension take whole bytes",
      );
    }
    return new Sha256Hasher();
  }

  /**
   * Hashes the input, up to its bit length when one is given.
   *
   * @param bytes - The input's bytes.
   * @param options - The bit length, if any.
   * @returns {Uint8Array} The digest.
   */
  protected override digest(bytes: Uint8Array, options?: Readonly<Sha256Options>): Uint8Array {
    if (options?.bitLength === undefined) return new Sha256Hasher().update(bytes).digest();
    assertOneRound(options, "a bit length measures the input, which only one round hashes");
    return sha256Bits(bytes, options.bitLength);
  }

  /**
   * Names the bit length with the digest, which belongs to that many bits and not to the bytes.
   *
   * @param options - The bit length, if any.
   * @returns {Record<string, unknown>} The bit length, or nothing.
   */
  protected override reported(options?: Readonly<Sha256Options>): Record<string, unknown> {
    return options?.bitLength === undefined ? {} : { bitLength: options.bitLength };
  }
}
