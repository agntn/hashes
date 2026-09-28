import { sha512 } from "@noble/hashes/sha2.js";
import { NobleHash } from "../core/noble.ts";

export class Sha512 extends NobleHash {
  static readonly key = "sha512";
  protected readonly hashFn = sha512;
  protected readonly about = {
    label: "SHA-512",
    description:
      "SHA-2 family 512-bit hash, the strongest SHA-2 variant, used for high-security applications",
    family: "cryptographic",
    digestLength: 64,
    securityNote: "512-bit security level",
  } as const;
}
