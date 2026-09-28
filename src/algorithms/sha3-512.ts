import { sha3_512 as hashFn } from "@noble/hashes/sha3.js";
import { defineNobleAlgorithm } from "../core/noble.ts";

export const sha3_512 = defineNobleAlgorithm({
  name: "sha3-512",
  label: "SHA3-512",
  description: "SHA-3 (Keccak) 512-bit hash, the strongest SHA-3 variant of the NIST standard",
  family: "cryptographic",
  hashFn,
  digestLength: 64,
  securityNote: "512-bit security level, sponge construction",
});
