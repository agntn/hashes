import { createHash } from "node:crypto";
import { FixedHash } from "../core/fixed-hash.ts";

export class Sha512Half extends FixedHash {
  static readonly key = "sha512-half";
  protected readonly about = {
    label: "SHA-512Half",
    description:
      "The first 32 bytes of SHA-512, the XRP Ledger's hash for transactions, ledger objects and signing",
    family: "cryptographic",
    digestLength: 32,
    securityNote:
      "256-bit output of SHA-512; not SHA-512/256, which starts from other initial values",
  } as const;

  /**
   * Computes SHA-512 and keeps its first half.
   *
   * @param bytes - Bytes to hash.
   * @returns {Uint8Array} The 32-byte hash.
   */
  protected digest(bytes: Uint8Array): Uint8Array {
    return createHash("sha512").update(bytes).digest().subarray(0, 32);
  }
}
