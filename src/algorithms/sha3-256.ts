import { NodeHash } from "../core/node-hash.ts";

export class Sha3_256 extends NodeHash {
  static readonly key = "sha3-256";
  protected readonly algorithm = "sha3-256";
  protected readonly about = {
    label: "SHA3-256",
    description:
      "SHA-3 (Keccak) 256-bit hash, the NIST standard with a different internal structure from SHA-2",
    family: "cryptographic",
    digestLength: 32,
    securityNote: "128-bit collision resistance, 256-bit preimage resistance, sponge construction",
  } as const;
}
