import { blake256 } from "../core/blake256.ts";
import { FixedHash } from "../core/fixed-hash.ts";

export class Blake256 extends FixedHash {
  static readonly key = "blake256";
  protected readonly about = {
    label: "BLAKE-256",
    description:
      "BLAKE-256 (14 rounds), the SHA-3 finalist Decred hashes blocks, transactions and addresses with",
    family: "BLAKE",
    category: "cryptographic",
    digestLength: 32,
    securityNote:
      "128-bit collision resistance, 256-bit preimage resistance. The original BLAKE, not BLAKE2 or BLAKE3",
  } as const;

  /**
   * Computes BLAKE-256.
   *
   * @param bytes - Bytes to hash.
   * @returns {Uint8Array} The 32-byte hash.
   */
  protected digest(bytes: Uint8Array): Uint8Array {
    return blake256(bytes);
  }
}
