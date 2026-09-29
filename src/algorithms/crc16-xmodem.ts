import { crc16Xmodem } from "../core/crc.ts";
import { FixedHash } from "../core/fixed-hash.ts";

export class Crc16Xmodem extends FixedHash {
  static readonly key = "crc16-xmodem";
  protected readonly about = {
    label: "CRC-16/XMODEM",
    description:
      "CRC-16/XMODEM (polynomial 0x1021, init 0), the checksum closing Stellar StrKeys and TON addresses",
    family: "CRC",
    category: "non-cryptographic",
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
    return crc16Xmodem(bytes);
  }
}
