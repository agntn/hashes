import { CRC64_VARIANTS, crc64, type Crc64Variant } from "../core/crc.ts";
import { FixedHash } from "../core/fixed-hash.ts";
import type { HashOptions } from "../core/types.ts";

/** Options CRC-64 takes besides the encoding. */
export interface Crc64Options extends HashOptions {
  /** Which CRC-64. Default: `xz`. */
  variant?: Crc64Variant;
}

export class Crc64 extends FixedHash<Crc64Options> {
  static readonly key = "crc64";
  protected readonly about = {
    label: "CRC-64",
    description:
      "CRC-64 from ECMA-182, reflected, the check xz writes after every block by default",
    family: "CRC",
    category: "non-cryptographic",
    digestLength: 8,
    securityNote: "NOT for security: error-detection checksum only",
  } as const;
  protected override readonly options = [
    {
      name: "variant",
      type: "string",
      required: false,
      default: "xz",
      choices: CRC64_VARIANTS,
      description: "Which CRC-64: xz, ECMA-182 reflected",
    },
  ] as const;

  /**
   * Computes CRC-64 in the chosen variant.
   *
   * @param bytes - Bytes to check.
   * @param options - The variant.
   * @returns {Uint8Array} The checksum, big-endian.
   */
  protected digest(bytes: Uint8Array, options?: Readonly<Crc64Options>): Uint8Array {
    return crc64(bytes, options?.variant);
  }

  /**
   * Reports the variant when one was asked for.
   *
   * @param options - The variant.
   * @returns {Record<string, unknown>} The variant used, or nothing for the default.
   */
  protected override reported(options?: Readonly<Crc64Options>): Record<string, unknown> {
    return options?.variant === undefined ? {} : { variant: options.variant };
  }
}
