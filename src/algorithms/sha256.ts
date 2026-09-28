import { sha256 } from "@noble/hashes/sha2.js";
import { NobleHash } from "../core/noble.ts";

export class Sha256 extends NobleHash {
  static readonly key = "sha256";
  protected readonly hashFn = sha256;
  protected readonly about = {
    label: "SHA-256",
    description:
      "SHA-2 family 256-bit hash, widely used for digital signatures, certificates, and integrity checks",
    family: "cryptographic",
    digestLength: 32,
    securityNote: "256-bit security level",
  } as const;
}
