/** XXH64 with a seed; the byte function lives in `src/core/xxhash.ts`. */
import { InvalidOptionError } from "../core/errors.ts";
import { FixedHash } from "../core/fixed-hash.ts";
import type { HashOptions } from "../core/types.ts";
import { xxh64 } from "../core/xxhash.ts";

/** Options xxHash takes besides the encoding. */
export interface XxhashOptions extends HashOptions {
  /** Unsigned 64-bit seed. Default: 0. */
  seed?: number | bigint | string;
}

/**
 * Reads the seed option as an unsigned 64-bit integer.
 *
 * @param seed - Seed as given.
 * @returns {bigint} The seed.
 */
function seedValue(seed: number | bigint | string | undefined): bigint {
  const exact = typeof seed === "string" && /^\d+$/.test(seed);
  const value =
    (typeof seed === "number" && Number.isSafeInteger(seed)) || exact ? BigInt(seed) : seed;
  if (value === undefined) return 0n;
  if (typeof value !== "bigint" || value < 0n || value > 0xffffffffffffffffn) {
    throw new InvalidOptionError("seed", String(seed), "must be an integer from 0 to 2^64-1");
  }
  return value;
}

export class Xxhash extends FixedHash<XxhashOptions> {
  static readonly key = "xxhash";
  protected readonly about = {
    label: "xxHash (XXH64)",
    description:
      "xxHash 64-bit, an extremely fast non-cryptographic hash used in databases and compression",
    family: "xxHash",
    category: "non-cryptographic",
    digestLength: 8,
    securityNote: "NOT for security: fast hash for hash tables, bloom filters, checksums",
  } as const;
  protected override readonly options = [
    {
      name: "seed",
      type: "number",
      required: false,
      default: 0,
      description: "Seed value for xxHash",
    },
  ] as const;

  /**
   * Computes XXH64 with the seed option.
   *
   * @param bytes - Bytes to hash.
   * @param options - The seed.
   * @returns {Uint8Array} The hash, big-endian.
   */
  protected digest(bytes: Uint8Array, options?: Readonly<XxhashOptions>): Uint8Array {
    return xxh64(bytes, seedValue(options?.seed));
  }

  /**
   * Reports the seed with the digest.
   *
   * @param options - The seed.
   * @returns {Record<string, unknown>} The seed used.
   */
  protected override reported(options?: Readonly<XxhashOptions>): Record<string, unknown> {
    return { seed: options?.seed ?? 0 };
  }
}
