import { BlockHash } from "../core/block-hash.ts";
import type { Hasher } from "../core/hasher.ts";
import { Sha512tHasher } from "../core/sha2.ts";

export class Sha512_224 extends BlockHash {
  static readonly key = "sha512-224";
  protected readonly about = {
    label: "SHA-512/224",
    description: "SHA-2 family 224-bit hash, SHA-512 with its own initial values cut to 28 bytes",
    family: "SHA",
    category: "cryptographic",
    digestLength: 28,
    securityNote:
      "112-bit collision resistance, 224-bit preimage resistance. Faster than SHA-224 on 64-bit machines",
  } as const;

  /**
   * Creates the hasher.
   *
   * @returns {Hasher} A fresh one.
   */
  hasher(): Hasher {
    return new Sha512tHasher(28);
  }
}
