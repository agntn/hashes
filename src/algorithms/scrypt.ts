import {
  isInputList,
  assertOneRound,
  ENCODING_OPTION,
  SALT_OPTION,
  encodeDigest,
  guarded,
  resolveSalt,
  toBytes,
  type SaltOptions,
} from "../core/digest.ts";
import { Hash } from "../core/hash.ts";
import { scrypt } from "../core/scrypt.ts";
import type { AlgorithmInfo, HashInput, HashOptions, HashResult } from "../core/types.ts";

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

export class Scrypt extends Hash {
  static readonly key = "scrypt";

  /**
   * Describes the algorithm.
   *
   * @returns {AlgorithmInfo} Its metadata.
   */
  info(): AlgorithmInfo {
    return {
      name: this.key,
      label: "scrypt",
      description: "scrypt password-based KDF, memory-hard, resistant to hardware attacks",
      family: "scrypt",
      category: "password",
      hmac: false,
      options: [
        ENCODING_OPTION,
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
      ],
      securityNote:
        "Memory-hard KDF. For passwords OWASP asks for N=2^17 with p=1, or N=2^14 with p=5 (r=8 in both). The default N=16384, p=1 is below that.",
    };
  }

  /**
   * Derives a key from the input.
   *
   * @param input - Text or bytes, or a list of them.
   * @param options - Encoding, salt and cost parameters.
   * @returns {HashResult | HashResult[]} The derived key, one per input for a list.
   */
  hash(input: HashInput, options?: Readonly<ScryptOptions>): HashResult;
  hash(inputs: readonly HashInput[], options?: Readonly<ScryptOptions>): HashResult[];
  hash(
    input: HashInput | readonly HashInput[],
    options?: Readonly<ScryptOptions>,
  ): HashResult | HashResult[] {
    if (isInputList(input)) return input.map((one) => this.hash(one, options));
    return guarded(this.key, () => {
      if (options?.key !== undefined) throw new Error(`${this.key} has no HMAC mode`);
      assertOneRound(options, `${this.key} sets its cost with its own parameters`);
      const { N, r, p, keyLength } = costParameters(options);
      const salt = resolveSalt(options);
      const raw = scrypt(toBytes(input), salt, N, r, p, keyLength);
      return encodeDigest(raw, this.key, "hash", options?.encoding ?? "hex", {
        N,
        r,
        p,
        keyLength,
        salt: salt.toHex(),
      });
    });
  }
}
