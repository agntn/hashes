import { adler32 } from "../core/adler32.ts";
import { FixedHash } from "../core/fixed-hash.ts";

export class Adler32 extends FixedHash {
  static readonly key = "adler32";
  protected readonly about = {
    label: "Adler-32",
    description: "Adler-32 from RFC 1950, the checksum at the end of every zlib stream",
    family: "Adler",
    category: "non-cryptographic",
    digestLength: 4,
    securityNote:
      "NOT for security: weaker than CRC-32 on short inputs, where its sums barely move",
  } as const;

  /**
   * Computes Adler-32.
   *
   * @param bytes - Bytes to check.
   * @returns {Uint8Array} The checksum, big-endian.
   */
  protected digest(bytes: Uint8Array): Uint8Array {
    return adler32(bytes);
  }
}
