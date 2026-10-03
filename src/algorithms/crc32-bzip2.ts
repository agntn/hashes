import { crc32Bzip2 } from "../core/crc.ts";
import { FixedHash } from "../core/fixed-hash.ts";

export class Crc32Bzip2 extends FixedHash {
  static readonly key = "crc32-bzip2";
  protected readonly about = {
    label: "CRC-32/BZIP2",
    description:
      "CRC-32/BZIP2, the zlib polynomial without reflection, which bzip2 stores per block and per stream",
    family: "CRC",
    category: "non-cryptographic",
    digestLength: 4,
    securityNote: "NOT for security: error-detection checksum only",
  } as const;

  /**
   * Computes CRC-32/BZIP2.
   *
   * @param bytes - Bytes to check.
   * @returns {Uint8Array} The checksum, big-endian.
   */
  protected digest(bytes: Uint8Array): Uint8Array {
    return crc32Bzip2(bytes);
  }
}
