import type { HashOption, HashOptions } from "./types.ts";

/** Options SHAKE128 and SHAKE256 take besides the encoding. */
export interface ShakeOptions extends HashOptions {
  /** Bytes to squeeze. Default: 32 for SHAKE128, 64 for SHAKE256, as OpenSSL picks them. */
  outputLength?: number;
}

/**
 * Declares `outputLength` with a sponge's default.
 *
 * @param defaultLength - Bytes squeezed when the option is left out.
 * @returns {HashOption} The option.
 */
export function outputLengthOption(defaultLength: number): HashOption {
  return {
    name: "outputLength",
    type: "number",
    required: false,
    default: defaultLength,
    description: "Bytes to squeeze, any whole number from 0",
  };
}

/**
 * Reads the output length, the default only when the option is left out: `null` is no length.
 *
 * @param options - The caller's options.
 * @param defaultLength - Bytes squeezed without the option.
 * @returns {number} The length, for the byte function to check.
 */
export function outputLength(
  options: Readonly<ShakeOptions> | undefined,
  defaultLength: number,
): number {
  if (options?.outputLength === undefined) return defaultLength;
  return options.outputLength;
}

/**
 * Reports the output length when one was asked for; the digest's own length says it anyway.
 *
 * @param options - The caller's options.
 * @returns {Record<string, unknown>} The length used, or nothing for the default.
 */
export function squeezed(options?: Readonly<ShakeOptions>): Record<string, unknown> {
  return options?.outputLength === undefined ? {} : { outputLength: options.outputLength };
}
