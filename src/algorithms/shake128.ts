import { FixedHash } from "../core/fixed-hash.ts";
import { shake128 } from "../core/keccak.ts";
import { outputLength, outputLengthOption, squeezed, type ShakeOptions } from "../core/shake.ts";

export class Shake128 extends FixedHash<ShakeOptions> {
  static readonly key = "shake128";
  protected readonly about = {
    label: "SHAKE128",
    description:
      "SHAKE128, the FIPS 202 sponge that squeezes as many bytes as you ask for, 32 unless outputLength says otherwise",
    family: "SHA",
    category: "cryptographic",
    digestLength: 32,
    securityNote:
      "128-bit security from 32 bytes of output up; shorter outputs give half their bits against collisions",
  } as const;
  protected override readonly options = [outputLengthOption(32)] as const;

  /**
   * Squeezes SHAKE128 to the asked length.
   *
   * @param bytes - Bytes to hash.
   * @param options - The output length.
   * @returns {Uint8Array} That many bytes, 32 by default.
   */
  protected digest(bytes: Uint8Array, options?: Readonly<ShakeOptions>): Uint8Array {
    return shake128(bytes, outputLength(options, 32));
  }

  /**
   * Reports the output length when one was asked for.
   *
   * @param options - The output length.
   * @returns {Record<string, unknown>} The length used, or nothing for the default.
   */
  protected override reported(options?: Readonly<ShakeOptions>): Record<string, unknown> {
    return squeezed(options);
  }
}
