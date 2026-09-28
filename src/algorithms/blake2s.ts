import { NodeHash } from "../core/node-hash.ts";

export class Blake2s extends NodeHash {
  static readonly key = "blake2s";
  protected readonly algorithm = "blake2s256";
  protected readonly about = {
    label: "BLAKE2s",
    description: "BLAKE2s 256-bit hash, optimized for 32-bit platforms, smaller state than BLAKE2b",
    family: "cryptographic",
    digestLength: 32,
    securityNote: "Up to 256-bit security level",
  } as const;
}
