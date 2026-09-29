import { BlockHash } from "../core/block-hash.ts";
import type { Hasher } from "../core/hasher.ts";
import { Sha512Hasher } from "../core/sha2.ts";

export class Sha512 extends BlockHash {
  static readonly key = "sha512";
  protected readonly about = {
    label: "SHA-512",
    description:
      "SHA-2 family 512-bit hash, the strongest SHA-2 variant, used for high-security applications",
    family: "SHA",
    category: "cryptographic",
    digestLength: 64,
    securityNote: "256-bit collision resistance, 512-bit preimage resistance",
  } as const;

  /**
   * Creates the hasher.
   *
   * @returns {Hasher} A fresh one.
   */
  hasher(): Hasher {
    return new Sha512Hasher();
  }
}
