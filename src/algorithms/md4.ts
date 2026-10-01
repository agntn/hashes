import { BlockHash } from "../core/block-hash.ts";
import type { Hasher } from "../core/hasher.ts";
import { Md4Hasher } from "../core/md4.ts";

export class Md4 extends BlockHash {
  static readonly key = "md4";
  protected readonly about = {
    label: "MD4",
    description: "MD4 128-bit hash, MD5's predecessor, BROKEN, still inside NTLM and eDonkey links",
    family: "MD",
    category: "legacy",
    digestLength: 16,
    securityNote:
      "BROKEN: practical collisions since 1996. Use only to reproduce NTLM hashes and old data.",
  } as const;

  /**
   * Creates the hasher.
   *
   * @returns {Hasher} A fresh one.
   */
  hasher(): Hasher {
    return new Md4Hasher();
  }
}
