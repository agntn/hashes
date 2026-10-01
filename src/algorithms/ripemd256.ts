import { BlockHash } from "../core/block-hash.ts";
import type { Hasher } from "../core/hasher.ts";
import { Ripemd256Hasher } from "../core/ripemd.ts";

export class Ripemd256 extends BlockHash {
  static readonly key = "ripemd256";
  protected readonly about = {
    label: "RIPEMD-256",
    description: "RIPEMD-256 256-bit hash, RIPEMD-128's two lines kept apart for a longer digest",
    family: "RIPEMD",
    category: "legacy",
    digestLength: 32,
    securityNote:
      "No stronger than RIPEMD-128: the wider digest adds no collision resistance, by design",
  } as const;

  /**
   * Creates the hasher.
   *
   * @returns {Hasher} A fresh one.
   */
  hasher(): Hasher {
    return new Ripemd256Hasher();
  }
}
