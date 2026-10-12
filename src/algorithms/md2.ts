import { BlockHash } from "../core/block-hash.ts";
import type { Hasher } from "../core/hasher.ts";
import { Md2Hasher } from "../core/md2.ts";

export class Md2 extends BlockHash {
  static readonly key = "md2";
  protected readonly about = {
    label: "MD2",
    description:
      "MD2 128-bit hash from 1989, BROKEN and slow, still in md2WithRSAEncryption certificates",
    family: "MD",
    category: "legacy",
    digestLength: 16,
    securityNote:
      "BROKEN: preimages in 2^73 and collisions in 2^63.3 (RFC 6149). Use only to check old data.",
  } as const;

  /**
   * Creates the hasher.
   *
   * @returns {Hasher} A fresh one.
   */
  hasher(): Hasher {
    return new Md2Hasher();
  }
}
