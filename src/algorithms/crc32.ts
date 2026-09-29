import { FixedHash } from "../core/fixed-hash.ts";

/**
 * CRC-32 lookup tables for slicing by eight: polynomial 0x04c11db7, reflected as 0xedb88320.
 * Table `k` at `256 * k` advances a byte's remainder through `k` more zero bytes.
 */
const TABLES = new Int32Array(256 * 8);
for (let index = 0; index < 256; index++) {
  let value = index;
  for (let bit = 0; bit < 8; bit++) value = value & 1 ? (value >>> 1) ^ 0xedb88320 : value >>> 1;
  TABLES[index] = value;
}
for (let index = 0; index < 256 * 7; index++) {
  const value = TABLES[index]!;
  TABLES[index + 256] = (value >>> 8) ^ TABLES[value & 0xff]!;
}

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
    const t = TABLES;
    const end = bytes.length - (bytes.length & 7);
    let crc = -1;
    let i = 0;
    for (; i < end; i += 8) {
      const low =
        crc ^ (bytes[i]! | (bytes[i + 1]! << 8) | (bytes[i + 2]! << 16) | (bytes[i + 3]! << 24));
      crc =
        t[1792 + (low & 0xff)]! ^
        t[1536 + ((low >>> 8) & 0xff)]! ^
        t[1280 + ((low >>> 16) & 0xff)]! ^
        t[1024 + (low >>> 24)]! ^
        t[768 + bytes[i + 4]!]! ^
        t[512 + bytes[i + 5]!]! ^
        t[256 + bytes[i + 6]!]! ^
        t[bytes[i + 7]!]!;
    }
    for (; i < bytes.length; i++) crc = (crc >>> 8) ^ t[(crc ^ bytes[i]!) & 0xff]!;
    const digest = new Uint8Array(4);
    new DataView(digest.buffer).setInt32(0, ~crc);
    return digest;
  }
}
