import { SALT_OPTION, resolveSalt, type SaltOptions } from "../core/digest.ts";
import { Kdf, type Derivation } from "../core/kdf.ts";
import { scrypt } from "../core/scrypt.ts";
import type { HashOptions } from "../core/types.ts";

/** Options scrypt takes besides the encoding. */
export interface ScryptOptions extends HashOptions, SaltOptions {
  /** CPU/memory cost, a power of 2. Default: 16384. */
  N?: number;
  /** Block size. Default: 8. */
  r?: number;
  /** Parallelization. Default: 1. */
  p?: number;
  /** Output key length in bytes. Default: 64. */
  keyLength?: number;
}

/**
 * Reads the cost options with their defaults.
 *
 * @param options - The scrypt options.
 * @returns {{ N: number, r: number, p: number, keyLength: number }} The cost parameters.
 */
function costParameters(options?: Readonly<ScryptOptions>) {
  const { N = 16384, r = 8, p = 1, keyLength = 64 } = options ?? {};
  return { N, r, p, keyLength };
}

export class Scrypt extends Kdf<ScryptOptions> {
  static readonly key = "scrypt";
  protected readonly about = {
    label: "scrypt",
    description: "scrypt password-based KDF, memory-hard, resistant to hardware attacks",
    family: "scrypt",
    category: "password",
    securityNote:
      "Memory-hard KDF. For passwords OWASP asks for N=2^17 with p=1, or N=2^14 with p=5 (r=8 in both). The default N=16384, p=1 is below that.",
  } as const;
  protected override readonly options = [
    SALT_OPTION,
    {
      name: "N",
      type: "number",
      required: false,
      default: 16384,
      description: "CPU/memory cost (power of 2)",
    },
    { name: "r", type: "number", required: false, default: 8, description: "Block size" },
    { name: "p", type: "number", required: false, default: 1, description: "Parallelization" },
    {
      name: "keyLength",
      type: "number",
      required: false,
      default: 64,
      description: "Output key length in bytes",
    },
  ] as const;

  /**
   * Derives a key with the cost parameters and the salt, drawn when missing.
   *
   * @param bytes - The input's bytes.
   * @param options - Salt and cost parameters.
   * @returns {Derivation} The key, with the salt and costs it reports.
   */
  protected derive(bytes: Uint8Array, options?: Readonly<ScryptOptions>): Derivation {
    const { N, r, p, keyLength } = costParameters(options);
    const salt = resolveSalt(options);
    return {
      digest: scrypt(bytes, salt, N, r, p, keyLength),
      reported: { N, r, p, keyLength, salt: salt.toHex() },
    };
  }
}
