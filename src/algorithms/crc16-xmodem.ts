import { FixedHash } from "../core/fixed-hash.ts";

/** CRC-16/XMODEM lookup table: polynomial 0x1021, not reflected. */
const TABLE = new Uint16Array(256);
for (let index = 0; index < 256; index++) {
  let value = index << 8;
  for (let bit = 0; bit < 8; bit++) {
    value = value & 0x8000 ? ((value << 1) ^ 0x1021) & 0xffff : (value << 1) & 0xffff;
  }
  TABLE[index] = value;
}

export class Crc16Xmodem extends FixedHash {
  static readonly key = "crc16-xmodem";
  protected readonly about = {
    label: "CRC-16/XMODEM",
    description:
      "CRC-16/XMODEM (polynomial 0x1021, init 0), the checksum closing Stellar StrKeys and TON addresses",
    family: "non-cryptographic",
    digestLength: 2,
    securityNote:
      "NOT for security. Printed big-endian as TON writes it; Stellar stores the two bytes the other way round",
  } as const;

  /**
   * Computes CRC-16/XMODEM.
   *
   * @param bytes - Bytes the checksum covers.
   * @returns {Uint8Array} The checksum, big-endian.
   */
  protected digest(bytes: Uint8Array): Uint8Array {
    let crc = 0;
    for (const byte of bytes) crc = ((crc << 8) & 0xffff) ^ TABLE[((crc >>> 8) ^ byte) & 0xff]!;
    return new Uint8Array([crc >>> 8, crc & 0xff]);
  }
}
