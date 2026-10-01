import { BlockHash } from "../core/block-hash.ts";
import type { Hasher } from "../core/hasher.ts";
import { Sha512tHasher } from "../core/sha2.ts";

export class Sha512_256 extends BlockHash {
  static readonly key = "sha512-256";
  protected readonly about = {
    label: "SHA-512/256",
    description: "SHA-2 family 256-bit hash, SHA-512 with its own initial values cut to 32 bytes",
    family: "SHA",
    category: "cryptographic",
    digestLength: 32,
    securityNote:
      "128-bit collision resistance, 256-bit preimage resistance. Not SHA-512Half, which keeps SHA-512's initial values",
  } as const;

  /**
   * Creates the hasher.
   *
   * @returns {Hasher} A fresh one.
   */
  hasher(): Hasher {
    return new Sha512tHasher(32);
  }
}
