import { NodeHash } from "../core/node-hash.ts";

export class Blake2b extends NodeHash {
  static readonly key = "blake2b";
  protected readonly algorithm = "blake2b512";
  protected readonly about = {
    label: "BLAKE2b",
    description:
      "BLAKE2b 512-bit hash, fast and secure, used by many modern protocols (Argon2, WireGuard)",
    family: "cryptographic",
    digestLength: 64,
    securityNote: "256-bit collision resistance, 512-bit preimage resistance",
  } as const;
}
