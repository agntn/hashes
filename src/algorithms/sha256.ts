import { BlockHash } from "../core/block-hash.ts";
import type { Hasher } from "../core/hasher.ts";
import { Sha256Hasher } from "../core/sha2.ts";

export class Sha256 extends BlockHash {
  static readonly key = "sha256";
  protected readonly about = {
    label: "SHA-256",
    description:
      "SHA-2 family 256-bit hash, widely used for digital signatures, certificates, and integrity checks",
    family: "cryptographic",
    digestLength: 32,
    securityNote: "128-bit collision resistance, 256-bit preimage resistance",
  } as const;

  /**
   * Creates the hasher.
   *
   * @returns {Hasher} A fresh one.
   */
  hasher(): Hasher {
    return new Sha256Hasher();
  }
}
