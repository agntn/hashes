import { crc32 } from "../core/crc.ts";
import { FixedHash } from "../core/fixed-hash.ts";

export class Crc32 extends FixedHash {
  static readonly key = "crc32";
  protected readonly about = {
    label: "CRC-32",
    description: "CRC-32 cyclic redundancy check, used in ZIP, PNG, gzip and network protocols",
    family: "CRC",
    category: "non-cryptographic",
    digestLength: 4,
    securityNote: "NOT for security: error-detection checksum only",
  } as const;

  /**
   * Computes CRC-32 as zlib does: initial value and final xor all ones.
   *
   * @param bytes - Bytes to check.
   * @returns {Uint8Array} The checksum, big-endian.
   */
  protected digest(bytes: Uint8Array): Uint8Array {
    return crc32(bytes);
  }
}
