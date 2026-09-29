import { FixedHash } from "../core/fixed-hash.ts";
import { sha512 } from "../core/sha2.ts";

export class Sha512Half extends FixedHash {
  static readonly key = "sha512-half";
  protected readonly about = {
    label: "SHA-512Half",
    description:
      "The first 32 bytes of SHA-512, the XRP Ledger's hash for transactions, ledger objects and signing",
    family: "cryptographic",
    digestLength: 32,
    securityNote:
      "128-bit collision resistance, 256-bit preimage resistance. Not SHA-512/256, which starts from other initial values",
  } as const;

  /**
   * Computes SHA-512 and keeps its first half.
   *
   * @param bytes - Bytes to hash.
   * @returns {Uint8Array} The 32-byte hash.
   */
  protected digest(bytes: Uint8Array): Uint8Array {
    return sha512(bytes).subarray(0, 32);
  }
}
