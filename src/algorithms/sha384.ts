import { BlockHash } from "../core/block-hash.ts";
import type { Hasher } from "../core/hasher.ts";
import { Sha512Hasher } from "../core/sha2.ts";

export class Sha384 extends BlockHash {
  static readonly key = "sha384";
  protected readonly about = {
    label: "SHA-384",
    description:
      "SHA-2 family 384-bit hash, a truncated SHA-512 used in TLS and government applications",
    family: "cryptographic",
    digestLength: 48,
    securityNote: "192-bit collision resistance, 384-bit preimage resistance",
  } as const;

  /**
   * Creates the hasher.
   *
   * @returns {Hasher} A fresh one.
   */
  protected hasher(): Hasher {
    return new Sha512Hasher(48);
  }
}
