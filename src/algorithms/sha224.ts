import { BlockHash } from "../core/block-hash.ts";
import type { Hasher } from "../core/hasher.ts";
import { Sha224Hasher } from "../core/sha2.ts";

export class Sha224 extends BlockHash {
  static readonly key = "sha224";
  protected readonly about = {
    label: "SHA-224",
    description: "SHA-2 family 224-bit hash, SHA-256 with its own initial values cut to 28 bytes",
    family: "SHA",
    category: "cryptographic",
    digestLength: 28,
    securityNote: "112-bit collision resistance, 224-bit preimage resistance",
  } as const;

  /**
   * Creates the hasher.
   *
   * @returns {Hasher} A fresh one.
   */
  hasher(): Hasher {
    return new Sha224Hasher();
  }
}
