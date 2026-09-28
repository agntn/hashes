import { NodeHash } from "../core/node-hash.ts";

export class Ripemd160 extends NodeHash {
  static readonly key = "ripemd160";
  protected readonly algorithm = "ripemd160";
  protected readonly about = {
    label: "RIPEMD-160",
    description:
      "RIPEMD-160 160-bit hash, used in Bitcoin address derivation (Hash160 = RIPEMD160(SHA256(x)))",
    family: "cryptographic",
    digestLength: 20,
    securityNote: "160-bit security level, used in Bitcoin",
  } as const;
}
