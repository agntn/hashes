import { BlockHash } from "../core/block-hash.ts";
import type { Hasher } from "../core/hasher.ts";
import { Md5Hasher } from "../core/md5.ts";

export class Md5 extends BlockHash {
  static readonly key = "md5";
  protected readonly about = {
    label: "MD5",
    description:
      "MD5 128-bit hash, BROKEN for security, still used for checksums and fingerprinting",
    family: "legacy",
    digestLength: 16,
    securityNote:
      "BROKEN: collision attacks known since 2004. Use only for non-security checksums.",
  } as const;

  /**
   * Creates the hasher.
   *
   * @returns {Hasher} A fresh one.
   */
  hasher(): Hasher {
    return new Md5Hasher();
  }
}
