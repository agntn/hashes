import { CRC24_VARIANTS, crc24, type Crc24Variant } from "../core/crc.ts";
import { FixedHash } from "../core/fixed-hash.ts";
import type { HashOptions } from "../core/types.ts";

/** Options CRC-24 takes besides the encoding. */
export interface Crc24Options extends HashOptions {
  /** Which CRC-24. Default: `openpgp`. */
  variant?: Crc24Variant;
}

export class Crc24 extends FixedHash<Crc24Options> {
  static readonly key = "crc24";
  protected readonly about = {
    label: "CRC-24",
    description:
      "CRC-24 from RFC 4880, the checksum after the = that closes an OpenPGP armored block",
    family: "CRC",
    category: "non-cryptographic",
    digestLength: 3,
    securityNote: "NOT for security: error-detection checksum only",
  } as const;
  protected override readonly options = [
    {
      name: "variant",
      type: "string",
      required: false,
      default: "openpgp",
      choices: CRC24_VARIANTS,
      description: "Which CRC-24: openpgp, as RFC 4880 armor writes it",
    },
  ] as const;

  /**
   * Computes CRC-24 in the chosen variant.
   *
   * @param bytes - Bytes to check.
   * @param options - The variant.
   * @returns {Uint8Array} The checksum, big-endian.
   */
  protected digest(bytes: Uint8Array, options?: Readonly<Crc24Options>): Uint8Array {
    return crc24(bytes, options?.variant);
  }

  /**
   * Reports the variant when one was asked for.
   *
   * @param options - The variant.
   * @returns {Record<string, unknown>} The variant used, or nothing for the default.
   */
  protected override reported(options?: Readonly<Crc24Options>): Record<string, unknown> {
    return options?.variant === undefined ? {} : { variant: options.variant };
  }
}
