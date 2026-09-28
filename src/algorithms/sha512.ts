import { NodeHash } from "../core/node-hash.ts";

export class Sha512 extends NodeHash {
  static readonly key = "sha512";
  protected readonly algorithm = "sha512";
  protected readonly about = {
    label: "SHA-512",
    description:
      "SHA-2 family 512-bit hash, the strongest SHA-2 variant, used for high-security applications",
    family: "cryptographic",
    digestLength: 64,
    securityNote: "256-bit collision resistance, 512-bit preimage resistance",
  } as const;
}
