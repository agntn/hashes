import { FixedHash } from "../core/fixed-hash.ts";
import { sha256d } from "../core/sha2.ts";

export class Sha256d extends FixedHash {
  static readonly key = "sha256d";
  protected readonly about = {
    label: "SHA256D (double SHA-256)",
    description:
      "SHA-256 of SHA-256, Bitcoin's transaction and block hash and the Base58Check checksum (its first 4 bytes)",
    family: "SHA",
    category: "cryptographic",
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
    return sha256d(bytes);
  }
}
