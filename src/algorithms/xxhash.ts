/** xxHash with a seed: XXH64, or XXH32 with `bits: 32`. The byte function lives in `src/core/xxhash.ts`. */
import { InvalidOptionError } from "../core/errors.ts";
import { FixedHash } from "../core/fixed-hash.ts";
import type { HashOptions } from "../core/types.ts";
import { XXHASH_BITS, xxhash, type XxhashBits } from "../core/xxhash.ts";

/** Options xxHash takes besides the encoding. */
export interface XxhashOptions extends HashOptions {
  /** 64 for XXH64, 32 for XXH32. Default: 64. */
  bits?: XxhashBits;
  /** Unsigned seed of `bits` bits. Default: 0. */
  seed?: number | bigint | string;
}

/**
 * Reads the seed option as an unsigned integer.
 *
 * @param seed - Seed as given.
 * @returns {bigint} The seed; `xxhash` checks it against the width.
 */
function seedValue(seed: number | bigint | string | undefined): bigint {
  const exact = typeof seed === "string" && /^\d+$/.test(seed);
  const value =
    (typeof seed === "number" && Number.isSafeInteger(seed)) || exact ? BigInt(seed) : seed;
  if (value === undefined) return 0n;
  if (typeof value !== "bigint") {
    throw new InvalidOptionError("seed", String(seed), "must be a non-negative integer");
  }
  return value;
}

export class Xxhash extends FixedHash<XxhashOptions> {
  static readonly key = "xxhash";
  protected readonly about = {
    label: "xxHash",
    description:
      "xxHash, an extremely fast non-cryptographic hash used in databases and compression: XXH64, or XXH32 with bits 32",
    family: "xxHash",
    category: "non-cryptographic",
    digestLength: 8,
    securityNote: "NOT for security: fast hash for hash tables, bloom filters, checksums",
  } as const;
  protected override readonly options = [
    {
      name: "bits",
      type: "number",
      required: false,
      default: 64,
      choices: XXHASH_BITS,
      description: "64 for XXH64, 32 for XXH32, the one lz4 frames use",
    },
    {
      name: "seed",
      type: "number",
      required: false,
      default: 0,
      description: "Seed value for xxHash",
    },
  ] as const;

  /**
   * Computes XXH64 or XXH32 with the seed option.
   *
   * @param bytes - Bytes to hash.
   * @param options - The seed.
   * @returns {Uint8Array} The hash, big-endian.
   */
  protected digest(bytes: Uint8Array, options?: Readonly<XxhashOptions>): Uint8Array {
    return xxhash(bytes, options?.bits, seedValue(options?.seed));
  }

  /**
   * Reports the seed with the digest.
   *
   * @param options - The seed.
   * @returns {Record<string, unknown>} The seed used.
   */
  protected override reported(options?: Readonly<XxhashOptions>): Record<string, unknown> {
    return options?.bits === undefined
      ? { seed: options?.seed ?? 0 }
      : { bits: options.bits, seed: options.seed ?? 0 };
  }
}
