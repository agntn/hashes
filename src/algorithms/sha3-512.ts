import { BlockHash } from "../core/block-hash.ts";
import type { Hasher } from "../core/hasher.ts";
import { KeccakHasher, SHA3_PADDING } from "../core/keccak.ts";

export class Sha3_512 extends BlockHash {
  static readonly key = "sha3-512";
  protected readonly about = {
    label: "SHA3-512",
    description: "SHA-3 (Keccak) 512-bit hash, the strongest SHA-3 variant of the NIST standard",
    family: "cryptographic",
    digestLength: 64,
    securityNote: "256-bit collision resistance, 512-bit preimage resistance, sponge construction",
  } as const;

  /**
   * Creates the hasher.
   *
   * @returns {Hasher} A fresh one.
   */
  hasher(): Hasher {
    return new KeccakHasher(64, SHA3_PADDING);
  }
}
