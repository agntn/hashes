import { BlockHash } from "../core/block-hash.ts";
import type { Hasher } from "../core/hasher.ts";
import { Sha0Hasher } from "../core/sha1.ts";

export class Sha0 extends BlockHash {
  static readonly key = "sha0";
  protected readonly about = {
    label: "SHA-0",
    description:
      "SHA-0 160-bit hash, the 1993 original withdrawn for SHA-1, BROKEN (full collision 2004)",
    family: "legacy",
    digestLength: 20,
    securityNote:
      "BROKEN: full collision found in 2004. Use only to reproduce old data, puzzles and papers.",
  } as const;

  /**
   * Creates the hasher.
   *
   * @returns {Hasher} A fresh one.
   */
  hasher(): Hasher {
    return new Sha0Hasher();
  }
}
