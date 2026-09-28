import { FixedHash } from "../core/fixed-hash.ts";
import { keccakSponge } from "../core/keccak.ts";

export class Keccak256 extends FixedHash {
  static readonly key = "keccak256";
  protected readonly about = {
    label: "Keccak-256",
    description:
      "Keccak-256 with the original padding, before SHA-3 changed it: Ethereum and EVM addresses, selectors and storage, Tron addresses, Monero",
    family: "cryptographic",
    digestLength: 32,
    securityNote:
      "256-bit output; differs from sha3-256 only in the padding byte, so the digests differ",
  } as const;

  /**
   * Computes Keccak-256.
   *
   * @param bytes - Bytes to hash.
   * @returns {Uint8Array} The 32-byte hash.
   */
  protected digest(bytes: Uint8Array): Uint8Array {
    return keccakSponge(bytes, 136, 0x01, 32);
  }
}
