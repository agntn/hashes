import { BlockHash } from "../core/block-hash.ts";
import type { Hasher } from "../core/hasher.ts";
import { Ripemd160Hasher } from "../core/ripemd160.ts";

export class Ripemd160 extends BlockHash {
  static readonly key = "ripemd160";
  protected readonly about = {
    label: "RIPEMD-160",
    description:
      "RIPEMD-160 160-bit hash, used in Bitcoin address derivation (Hash160 = RIPEMD160(SHA256(x)))",
    family: "cryptographic",
    digestLength: 20,
    securityNote: "80-bit collision resistance, 160-bit preimage resistance",
  } as const;

  /**
   * Creates the hasher.
   *
   * @returns {Hasher} A fresh one.
   */
  hasher(): Hasher {
    return new Ripemd160Hasher();
  }
}
