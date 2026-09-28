import { NodeHash } from "../core/node-hash.ts";

export class Sha3_512 extends NodeHash {
  static readonly key = "sha3-512";
  protected readonly algorithm = "sha3-512";
  protected readonly about = {
    label: "SHA3-512",
    description: "SHA-3 (Keccak) 512-bit hash, the strongest SHA-3 variant of the NIST standard",
    family: "cryptographic",
    digestLength: 64,
    securityNote: "512-bit security level, sponge construction",
  } as const;
}
