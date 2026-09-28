import { NodeHash } from "../core/node-hash.ts";

export class Sha256 extends NodeHash {
  static readonly key = "sha256";
  protected readonly algorithm = "sha256";
  protected readonly about = {
    label: "SHA-256",
    description:
      "SHA-2 family 256-bit hash, widely used for digital signatures, certificates, and integrity checks",
    family: "cryptographic",
    digestLength: 32,
    securityNote: "128-bit collision resistance, 256-bit preimage resistance",
  } as const;
}
