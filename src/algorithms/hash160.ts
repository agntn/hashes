import { createHash } from "node:crypto";
import { FixedHash } from "../core/fixed-hash.ts";

export class Hash160 extends FixedHash {
  static readonly key = "hash160";
  protected readonly about = {
    label: "HASH160",
    description:
      "RIPEMD-160 of SHA-256, the public key and script hash behind Bitcoin, Litecoin, Dogecoin, Dash, Bitcoin Cash, Zcash and XRP Ledger addresses",
    family: "cryptographic",
    digestLength: 20,
    securityNote: "160-bit output, collision resistance of RIPEMD-160",
  } as const;

  /**
   * Computes RIPEMD-160(SHA-256(bytes)).
   *
   * @param bytes - Bytes to hash, usually a public key or a script.
   * @returns {Uint8Array} The 20-byte hash.
   */
  protected digest(bytes: Uint8Array): Uint8Array {
    return createHash("ripemd160").update(createHash("sha256").update(bytes).digest()).digest();
  }
}
