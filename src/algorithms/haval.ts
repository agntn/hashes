import { BlockHash } from "../core/block-hash.ts";
import {
  HAVAL_BITS,
  HAVAL_PASSES,
  HavalHasher,
  type HavalBits,
  type HavalPasses,
} from "../core/haval.ts";
import type { Hasher } from "../core/hasher.ts";
import type { HashOptions } from "../core/types.ts";

/** Options HAVAL takes besides the encoding and the HMAC key. */
export interface HavalOptions extends HashOptions {
  /** Passes over each block: 3, 4 or 5. Default: 3. */
  passes?: HavalPasses;
  /** Fingerprint length in bits: 128, 160, 192, 224 or 256. Default: 128. */
  bits?: HavalBits;
}

export class Haval extends BlockHash<HavalOptions> {
  static readonly key = "haval";
  protected readonly about = {
    label: "HAVAL",
    description:
      "HAVAL from 1992, 3 to 5 passes and 128 to 256 bits, BROKEN, still in PHP's hash() and mhash",
    family: "HAVAL",
    category: "legacy",
    digestLength: 16,
    securityNote:
      "BROKEN: practical collisions with 3 passes (2^29, 2003) and 4 passes (2^36, 2006); 5-pass HAVAL-256 in 2^123, under its birthday bound. Use only to check old data.",
  } as const;
  protected override readonly options = [
    {
      name: "passes",
      type: "number",
      required: false,
      default: 3,
      choices: HAVAL_PASSES,
      description: "Passes over each block, 3, 4 or 5, as the reference haval.h numbers them",
    },
    {
      name: "bits",
      type: "number",
      required: false,
      default: 128,
      choices: HAVAL_BITS,
      description: "Fingerprint length in bits, 128 to 256 in steps of 32",
    },
  ] as const;

  /**
   * Creates the hasher.
   *
   * @param options - Passes and fingerprint length.
   * @returns {Hasher} A fresh one.
   */
  hasher(options?: Readonly<HavalOptions>): Hasher {
    return new HavalHasher(options?.passes, options?.bits);
  }

  /**
   * Names the variant with every digest, defaults included: a HAVAL digest without it is a guess.
   *
   * @param options - Passes and fingerprint length.
   * @returns {Record<string, unknown>} The passes and bits used.
   */
  protected override reported(options?: Readonly<HavalOptions>): Record<string, unknown> {
    return { passes: options?.passes ?? 3, bits: options?.bits ?? 128 };
  }
}
