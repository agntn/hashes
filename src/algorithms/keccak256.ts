import { NodeHash } from "../core/node-hash.ts";

export class Keccak256 extends NodeHash {
  static readonly key = "keccak256";
  protected readonly algorithm = "keccak-256";
  protected readonly about = {
    label: "Keccak-256",
    description:
      "Keccak-256 with the original padding, before SHA-3 changed it: Ethereum and EVM addresses, selectors and storage, Tron addresses, Monero",
    family: "cryptographic",
    digestLength: 32,
    securityNote:
      "128-bit collision resistance, 256-bit preimage resistance. Differs from sha3-256 only in the padding byte, so the digests differ",
  } as const;
}
