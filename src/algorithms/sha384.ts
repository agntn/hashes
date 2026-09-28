import { NodeHash } from "../core/node-hash.ts";

export class Sha384 extends NodeHash {
  static readonly key = "sha384";
  protected readonly algorithm = "sha384";
  protected readonly about = {
    label: "SHA-384",
    description:
      "SHA-2 family 384-bit hash, a truncated SHA-512 used in TLS and government applications",
    family: "cryptographic",
    digestLength: 48,
    securityNote: "384-bit security level",
  } as const;
}
