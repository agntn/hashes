import { createHash } from "node:crypto";
import { FixedHash } from "../core/fixed-hash.ts";

export class Hash256 extends FixedHash {
  static readonly key = "hash256";
  protected readonly about = {
    label: "HASH256 (double SHA-256)",
    description:
      "SHA-256 of SHA-256, Bitcoin's transaction and block hash and the Base58Check checksum (its first 4 bytes)",
    family: "cryptographic",
    digestLength: 32,
    securityNote:
      "128-bit collision resistance, 256-bit preimage resistance. Printed in hash order; block explorers show txids and block hashes byte-reversed",
  } as const;

  /**
   * Computes SHA-256(SHA-256(bytes)).
   *
   * @param bytes - Bytes to hash, such as a serialized transaction.
   * @returns {Uint8Array} The 32-byte hash.
   */
  protected digest(bytes: Uint8Array): Uint8Array {
    return createHash("sha256").update(createHash("sha256").update(bytes).digest()).digest();
  }
}
