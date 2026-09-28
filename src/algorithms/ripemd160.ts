import { ripemd160 } from "@noble/hashes/legacy.js";
import { NobleHash } from "../core/noble.ts";

export class Ripemd160 extends NobleHash {
  static readonly key = "ripemd160";
  protected readonly hashFn = ripemd160;
  protected readonly about = {
    label: "RIPEMD-160",
    description:
      "RIPEMD-160 160-bit hash, used in Bitcoin address derivation (Hash160 = RIPEMD160(SHA256(x)))",
    family: "cryptographic",
    digestLength: 20,
    securityNote: "160-bit security level, used in Bitcoin",
  } as const;
}
