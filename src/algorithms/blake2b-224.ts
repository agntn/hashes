import { blake2b } from "../core/blake2b.ts";
import { FixedHash } from "../core/fixed-hash.ts";

export class Blake2b224 extends FixedHash {
  static readonly key = "blake2b-224";
  protected readonly about = {
    label: "BLAKE2b-224",
    description:
      "BLAKE2b with a 28-byte output, Cardano's hash of payment and stake keys and scripts in its addresses",
    family: "cryptographic",
    digestLength: 28,
    securityNote:
      "112-bit collision resistance, 224-bit preimage resistance. Not a truncation of the longer blake2b forms",
  } as const;

  /**
   * Computes BLAKE2b with a 28-byte output.
   *
   * @param bytes - Bytes to hash.
   * @returns {Uint8Array} The 28-byte hash.
   */
  protected digest(bytes: Uint8Array): Uint8Array {
    return blake2b(bytes, 28);
  }
}
