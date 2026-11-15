import { FixedHash } from "../core/fixed-hash.ts";
import { shake256 } from "../core/keccak.ts";
import { outputLength, outputLengthOption, squeezed, type ShakeOptions } from "../core/shake.ts";

export class Shake256 extends FixedHash<ShakeOptions> {
  static readonly key = "shake256";
  protected readonly about = {
    label: "SHAKE256",
    description:
      "SHAKE256, the FIPS 202 sponge that squeezes as many bytes as you ask for, 64 unless outputLength says otherwise; Ed448 takes 114",
    family: "SHA",
    category: "cryptographic",
    digestLength: 64,
    securityNote:
      "256-bit security from 64 bytes of output up; shorter outputs give half their bits against collisions",
  } as const;
  protected override readonly options = [outputLengthOption(64)] as const;

  /**
   * Squeezes SHAKE256 to the asked length.
   *
   * @param bytes - Bytes to hash.
   * @param options - The output length.
   * @returns {Uint8Array} That many bytes, 64 by default.
   */
  protected digest(bytes: Uint8Array, options?: Readonly<ShakeOptions>): Uint8Array {
    return shake256(bytes, outputLength(options, 64));
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
