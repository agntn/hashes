import { BlockHash } from "../core/block-hash.ts";
import type { Hasher } from "../core/hasher.ts";
import { Ripemd128Hasher } from "../core/ripemd.ts";

export class Ripemd128 extends BlockHash {
  static readonly key = "ripemd128";
  protected readonly about = {
    label: "RIPEMD-128",
    description: "RIPEMD-128 128-bit hash, the four-round RIPEMD that replaced the original RIPEMD",
    family: "RIPEMD",
    category: "legacy",
    digestLength: 16,
    securityNote:
      "64-bit collision resistance, 128-bit preimage resistance. Too short for new designs",
  } as const;

  /**
   * Creates the hasher.
   *
   * @returns {Hasher} A fresh one.
   */
  hasher(): Hasher {
    return new Ripemd128Hasher();
  }
}
