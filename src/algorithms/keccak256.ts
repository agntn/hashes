import { BlockHash } from "../core/block-hash.ts";
import type { Hasher } from "../core/hasher.ts";
import { KECCAK_PADDING, KeccakHasher } from "../core/keccak.ts";

export class Keccak256 extends BlockHash {
  static readonly key = "keccak256";
  protected readonly about = {
    label: "Keccak-256",
    description:
      "Keccak-256 with the original padding, before SHA-3 changed it: Ethereum and EVM addresses, selectors and storage, Tron addresses, Monero",
    family: "cryptographic",
    digestLength: 32,
    securityNote:
      "128-bit collision resistance, 256-bit preimage resistance. Differs from sha3-256 only in the padding byte, so the digests differ",
  } as const;

  /**
   * Creates the hasher.
   *
   * @returns {Hasher} A fresh one.
   */
  protected hasher(): Hasher {
    return new KeccakHasher(32, KECCAK_PADDING);
  }
}
