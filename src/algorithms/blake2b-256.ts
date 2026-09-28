import { blake2b } from "../core/blake2b.ts";
import { FixedHash } from "../core/fixed-hash.ts";

export class Blake2b256 extends FixedHash {
  static readonly key = "blake2b-256";
  protected readonly about = {
    label: "BLAKE2b-256",
    description:
      "BLAKE2b with a 32-byte output, the address hash of Sui and the transaction id of Cardano",
    family: "cryptographic",
    digestLength: 32,
    securityNote:
      "256-bit output; not the first half of the 64-byte blake2b, the length is hashed in",
  } as const;

  /**
   * Computes BLAKE2b with a 32-byte output.
   *
   * @param bytes - Bytes to hash.
   * @returns {Uint8Array} The 32-byte hash.
   */
  protected digest(bytes: Uint8Array): Uint8Array {
    return blake2b(bytes, 32);
  }
}
