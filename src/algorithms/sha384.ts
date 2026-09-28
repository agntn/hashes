import { sha384 } from "@noble/hashes/sha2.js";
import { NobleHash } from "../core/noble.ts";

export class Sha384 extends NobleHash {
  static readonly key = "sha384";
  protected readonly hashFn = sha384;
  protected readonly about = {
    label: "SHA-384",
    description:
      "SHA-2 family 384-bit hash, a truncated SHA-512 used in TLS and government applications",
    family: "cryptographic",
    digestLength: 48,
    securityNote: "384-bit security level",
  } as const;
}
