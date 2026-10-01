import { BlockHash } from "../core/block-hash.ts";
import type { Hasher } from "../core/hasher.ts";
import { Ripemd320Hasher } from "../core/ripemd.ts";

export class Ripemd320 extends BlockHash {
  static readonly key = "ripemd320";
  protected readonly about = {
    label: "RIPEMD-320",
    description: "RIPEMD-320 320-bit hash, RIPEMD-160's two lines kept apart for a longer digest",
    family: "RIPEMD",
    category: "cryptographic",
    digestLength: 40,
    securityNote:
      "No stronger than RIPEMD-160: the wider digest adds no collision resistance, by design",
  } as const;

  /**
   * Creates the hasher.
   *
   * @returns {Hasher} A fresh one.
   */
  hasher(): Hasher {
    return new Ripemd320Hasher();
  }
}
