import { blake3 } from "@noble/hashes/blake3.js";
import { NobleHash } from "../core/noble.ts";

export class Blake3 extends NobleHash {
  static readonly key = "blake3";
  protected readonly hashFn = blake3;
  protected override readonly hmac = false;
  protected readonly about = {
    label: "BLAKE3",
    description: "BLAKE3, an extremely fast cryptographic hash, parallelizable, 256-bit output",
    family: "cryptographic",
    digestLength: 32,
    securityNote: "256-bit security level, Merkle tree structure for parallelism",
  } as const;
}
