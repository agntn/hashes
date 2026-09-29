import { BlockHash } from "../core/block-hash.ts";
import type { Hasher } from "../core/hasher.ts";
import { Blake2sHasher } from "../core/blake2s.ts";

export class Blake2s extends BlockHash {
  static readonly key = "blake2s";
  protected readonly about = {
    label: "BLAKE2s",
    description:
      "BLAKE2s 256-bit hash, optimized for 32-bit platforms, smaller state than BLAKE2b, used by WireGuard",
    family: "BLAKE",
    category: "cryptographic",
    digestLength: 32,
    securityNote: "128-bit collision resistance, 256-bit preimage resistance",
  } as const;

  /**
   * Creates the hasher.
   *
   * @returns {Hasher} A fresh one.
   */
  hasher(): Hasher {
    return new Blake2sHasher();
  }
}
