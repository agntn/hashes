import { crc32 } from "node:zlib";
import { FixedHash } from "../core/fixed-hash.ts";

export class Crc32 extends FixedHash {
  static readonly key = "crc32";
  protected readonly about = {
    label: "CRC-32",
    description: "CRC-32 cyclic redundancy check, used in ZIP, PNG, gzip and network protocols",
    family: "non-cryptographic",
    digestLength: 4,
    securityNote: "NOT for security: error-detection checksum only",
  } as const;

  /**
   * Computes CRC-32 through zlib.
   *
   * @param bytes - Bytes to check.
   * @returns {Uint8Array} The checksum, big-endian.
   */
  protected digest(bytes: Uint8Array): Uint8Array {
    const digest = new Uint8Array(4);
    new DataView(digest.buffer).setUint32(0, crc32(bytes));
    return digest;
  }
}
