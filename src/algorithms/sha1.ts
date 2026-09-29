import { BlockHash } from "../core/block-hash.ts";
import type { Hasher } from "../core/hasher.ts";
import { Sha1Hasher } from "../core/sha1.ts";

export class Sha1 extends BlockHash {
  static readonly key = "sha1";
  protected readonly about = {
    label: "SHA-1",
    description:
      "SHA-1 160-bit hash, BROKEN for security (SHAttered 2017), still used in Git and legacy systems",
    family: "legacy",
    digestLength: 20,
    securityNote:
      "BROKEN: practical collision attack (SHAttered). Use only for legacy compatibility.",
  } as const;

  /**
   * Creates the hasher.
   *
   * @returns {Hasher} A fresh one.
   */
  protected hasher(): Hasher {
    return new Sha1Hasher();
  }
}
