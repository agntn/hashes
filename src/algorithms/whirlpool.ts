import { BlockHash } from "../core/block-hash.ts";
import type { Hasher } from "../core/hasher.ts";
import { WhirlpoolHasher } from "../core/whirlpool.ts";

export class Whirlpool extends BlockHash {
  static readonly key = "whirlpool";
  protected readonly about = {
    label: "Whirlpool",
    description:
      "Whirlpool 512-bit hash, the final 2003 revision in ISO/IEC 10118-3 and VeraCrypt, not Whirlpool-0 or Whirlpool-T",
    family: "Whirlpool",
    category: "cryptographic",
    digestLength: 64,
    securityNote:
      "No attack on the full hash. Collisions reach 5.5 of its 10 rounds, a distinguisher the full compression function. The digest is the whole state, so a secret prefix is no MAC: use HMAC.",
  } as const;

  /**
   * Creates the hasher.
   *
   * @returns {Hasher} A fresh one.
   */
  hasher(): Hasher {
    return new WhirlpoolHasher();
  }
}
