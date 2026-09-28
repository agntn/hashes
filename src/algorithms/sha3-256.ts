import { sha3_256 } from "@noble/hashes/sha3.js";
import { NobleHash } from "../core/noble.ts";

export class Sha3_256 extends NobleHash {
  static readonly key = "sha3-256";
  protected readonly hashFn = sha3_256;
  protected readonly about = {
    label: "SHA3-256",
    description:
      "SHA-3 (Keccak) 256-bit hash, the NIST standard with a different internal structure from SHA-2",
    family: "cryptographic",
    digestLength: 32,
    securityNote: "256-bit security level, sponge construction",
  } as const;
}
