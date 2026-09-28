import { blake2b } from "@noble/hashes/blake2.js";
import { NobleHash } from "../core/noble.ts";

export class Blake2b extends NobleHash {
  static readonly key = "blake2b";
  protected readonly hashFn = blake2b;
  protected readonly about = {
    label: "BLAKE2b",
    description:
      "BLAKE2b 512-bit hash, fast and secure, used by many modern protocols (Argon2, WireGuard)",
    family: "cryptographic",
    digestLength: 64,
    securityNote: "Up to 512-bit security level",
  } as const;
}
