import { BlockHash } from "../core/block-hash.ts";
import type { Hasher } from "../core/hasher.ts";
import { KeccakHasher, SHA3_PADDING } from "../core/keccak.ts";

export class Sha3_256 extends BlockHash {
  static readonly key = "sha3-256";
  protected readonly about = {
    label: "SHA3-256",
    description:
      "SHA-3 (Keccak) 256-bit hash, the NIST standard with a different internal structure from SHA-2",
    family: "cryptographic",
    digestLength: 32,
    securityNote: "128-bit collision resistance, 256-bit preimage resistance, sponge construction",
  } as const;

  /**
   * Creates the hasher.
   *
   * @returns {Hasher} A fresh one.
   */
  protected hasher(): Hasher {
    return new KeccakHasher(32, SHA3_PADDING);
  }
}
