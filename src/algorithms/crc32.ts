import { CRC32_VARIANTS, crc32, type Crc32Variant } from "../core/crc.ts";
import { FixedHash } from "../core/fixed-hash.ts";
import type { HashOptions } from "../core/types.ts";

/** Options CRC-32 takes besides the encoding. */
export interface Crc32Options extends HashOptions {
  /** Which CRC-32: `iso-hdlc` (zlib, gzip, ZIP, PNG) or `bzip2`. Default: `iso-hdlc`. */
  variant?: Crc32Variant;
}

export class Crc32 extends FixedHash<Crc32Options> {
  static readonly key = "crc32";
  protected readonly about = {
    label: "CRC-32",
    description:
      "CRC-32 cyclic redundancy check, used in ZIP, PNG, gzip and network protocols, and unreflected in bzip2",
    family: "CRC",
    category: "non-cryptographic",
    digestLength: 4,
    securityNote: "NOT for security: error-detection checksum only",
  } as const;
  protected override readonly options = [
    {
      name: "variant",
      type: "string",
      required: false,
      default: "iso-hdlc",
      choices: CRC32_VARIANTS,
      description: "Which CRC-32: iso-hdlc as zlib, gzip, ZIP and PNG compute it, or bzip2",
    },
  ] as const;

  /**
   * Computes CRC-32 in the chosen variant.
   *
   * @param bytes - Bytes to check.
   * @param options - The variant.
   * @returns {Uint8Array} The checksum, big-endian.
   */
  protected digest(bytes: Uint8Array, options?: Readonly<Crc32Options>): Uint8Array {
    return crc32(bytes, options?.variant);
  }

  /**
   * Reports the variant when one was asked for.
   *
   * @param options - The variant.
   * @returns {Record<string, unknown>} The variant used, or nothing for the default.
   */
  protected override reported(options?: Readonly<Crc32Options>): Record<string, unknown> {
    return options?.variant === undefined ? {} : { variant: options.variant };
  }
}
