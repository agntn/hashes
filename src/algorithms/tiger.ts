import { BlockHash } from "../core/block-hash.ts";
import type { Hasher } from "../core/hasher.ts";
import { TigerHasher } from "../core/tiger.ts";

export class Tiger extends BlockHash {
  static readonly key = "tiger";
  protected readonly about = {
    label: "Tiger",
    description:
      "Tiger 192-bit hash from 1996, the original with 0x01 padding, in Tiger Tree Hashes on Direct Connect and Gnutella",
    family: "Tiger",
    category: "legacy",
    digestLength: 24,
    securityNote:
      "No practical attack on all 24 rounds, but collisions reach 19 of them (2^62) and pseudo-near-collisions the full function. Use only to check old data.",
  } as const;

  /**
   * Creates the hasher.
   *
   * @returns {Hasher} A fresh one.
   */
  hasher(): Hasher {
    return new TigerHasher();
  }
}
