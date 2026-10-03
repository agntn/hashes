import { crc64Xz } from "../core/crc.ts";
import { FixedHash } from "../core/fixed-hash.ts";

export class Crc64Xz extends FixedHash {
  static readonly key = "crc64-xz";
  protected readonly about = {
    label: "CRC-64/XZ",
    description:
      "CRC-64/XZ (ECMA-182, reflected), the check xz writes after every block by default",
    family: "CRC",
    category: "non-cryptographic",
    digestLength: 8,
    securityNote: "NOT for security: error-detection checksum only",
  } as const;

  /**
   * Computes CRC-64/XZ.
   *
   * @param bytes - Bytes to check.
   * @returns {Uint8Array} The checksum, big-endian.
   */
  protected digest(bytes: Uint8Array): Uint8Array {
    return crc64Xz(bytes);
  }
}
