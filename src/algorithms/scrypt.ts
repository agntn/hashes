import { scrypt as nobleScrypt } from "@noble/hashes/scrypt.js";
import {
  ENCODING_OPTION,
  SALT_OPTION,
  encodeDigest,
  guarded,
  resolveSalt,
  toBytes,
  type SaltOptions,
} from "../core/digest.ts";
import { InvalidOptionError } from "../core/errors.ts";
import type { AlgorithmEntry, HashAlgorithm, HashInput, HashOptions } from "../core/types.ts";

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
  if (!Number.isInteger(N) || N < 2 || (N & (N - 1)) !== 0) {
    throw new InvalidOptionError("N", N, "must be a power of 2 and >= 2");
  }
  return { N, r, p, keyLength };
}

const algorithm: HashAlgorithm = {
  name: () => "scrypt",
  info: () => ({
    name: "scrypt",
    label: "scrypt",
    description: "scrypt password-based KDF, memory-hard, resistant to hardware attacks",
    family: "password",
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
  }),
  hash: (input: HashInput, options?: Readonly<ScryptOptions>) =>
    guarded("scrypt", () => {
      const { N, r, p, keyLength } = costParameters(options);
      const salt = resolveSalt(options);
      const raw = nobleScrypt(toBytes(input), salt, { N, r, p, dkLen: keyLength });
      return encodeDigest(raw, "scrypt", "hash", options?.encoding ?? "hex", {
        N,
        r,
        p,
        keyLength,
        salt: Buffer.from(salt).toString("hex"),
      });
    }),
};

export const scrypt: AlgorithmEntry = { name: "scrypt", create: () => algorithm };
