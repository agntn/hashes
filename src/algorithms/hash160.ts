import { FixedHash } from "../core/fixed-hash.ts";
import { Ripemd160Hasher } from "../core/ripemd160.ts";
import { sha256 } from "../core/sha2.ts";

export class Hash160 extends FixedHash {
  static readonly key = "hash160";
  protected readonly about = {
    label: "HASH160",
    description:
      "RIPEMD-160 of SHA-256, the public key and script hash behind Bitcoin, Litecoin, Dogecoin, Dash, Bitcoin Cash, Zcash and XRP Ledger addresses",
    family: "cryptographic",
    digestLength: 20,
    securityNote: "80-bit collision resistance, 160-bit preimage resistance, bounded by RIPEMD-160",
  } as const;

  /**
   * Computes RIPEMD-160(SHA-256(bytes)).
   *
   * @param bytes - Bytes to hash, usually a public key or a script.
   * @returns {Uint8Array} The 20-byte hash.
   */
  protected digest(bytes: Uint8Array): Uint8Array {
    return new Ripemd160Hasher().update(sha256(bytes)).digest();
  }
}
