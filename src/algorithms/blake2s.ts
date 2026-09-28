import { blake2s } from "@noble/hashes/blake2.js";
import { NobleHash } from "../core/noble.ts";

export class Blake2s extends NobleHash {
  static readonly key = "blake2s";
  protected readonly hashFn = blake2s;
  protected readonly about = {
    label: "BLAKE2s",
    description: "BLAKE2s 256-bit hash, optimized for 32-bit platforms, smaller state than BLAKE2b",
    family: "cryptographic",
    digestLength: 32,
    securityNote: "Up to 256-bit security level",
  } as const;
}
