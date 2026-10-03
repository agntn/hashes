import { InvalidOptionError } from "../core/errors.ts";
import { FixedHash } from "../core/fixed-hash.ts";
import type { HashOptions } from "../core/types.ts";
import { xxh32 } from "../core/xxhash.ts";

/** Options XXH32 takes besides the encoding. */
export interface Xxhash32Options extends HashOptions {
  /** Unsigned 32-bit seed. Default: 0. */
  seed?: number | string;
}

/**
 * Reads the seed option as an unsigned 32-bit integer.
 *
 * @param seed - Seed as given.
 * @returns {number} The seed.
 */
function seedValue(seed: number | string | undefined): number {
  if (seed === undefined) return 0;
  const value = typeof seed === "string" && /^\d+$/u.test(seed) ? Number(seed) : seed;
  if (typeof value !== "number" || !Number.isInteger(value) || value < 0 || value > 0xffffffff) {
    throw new InvalidOptionError("seed", String(seed), "must be an integer from 0 to 2^32-1");
  }
  return value;
}

export class Xxhash32 extends FixedHash<Xxhash32Options> {
  static readonly key = "xxhash32";
  protected readonly about = {
    label: "xxHash (XXH32)",
    description: "xxHash 32-bit, the checksum of lz4 frames and their blocks",
    family: "xxHash",
    category: "non-cryptographic",
    digestLength: 4,
    securityNote: "NOT for security: fast hash for hash tables and checksums",
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
   * Computes XXH32 with the seed option.
   *
   * @param bytes - Bytes to hash.
   * @param options - The seed.
   * @returns {Uint8Array} The hash, big-endian.
   */
  protected digest(bytes: Uint8Array, options?: Readonly<Xxhash32Options>): Uint8Array {
    return xxh32(bytes, seedValue(options?.seed));
  }

  /**
   * Reports the seed with the digest.
   *
   * @param options - The seed.
   * @returns {Record<string, unknown>} The seed used.
   */
  protected override reported(options?: Readonly<Xxhash32Options>): Record<string, unknown> {
    return { seed: options?.seed ?? 0 };
  }
}
