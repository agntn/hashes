import { BlockHash } from "../core/block-hash.ts";
import type { Hasher } from "../core/hasher.ts";
import { Blake2bHasher } from "../core/blake2b.ts";

export class Blake2b extends BlockHash {
  static readonly key = "blake2b";
  protected readonly about = {
    label: "BLAKE2b",
    description:
      "BLAKE2b 512-bit hash, fast and secure, used by many modern protocols (Argon2, WireGuard)",
    family: "cryptographic",
    digestLength: 64,
    securityNote: "256-bit collision resistance, 512-bit preimage resistance",
  } as const;

  /**
   * Creates the hasher.
   *
   * @returns {Hasher} A fresh one.
   */
  protected hasher(): Hasher {
    return new Blake2bHasher(64);
  }
}
