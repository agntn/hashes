import { sha3_256 as hashFn } from "@noble/hashes/sha3.js";
import { defineNobleAlgorithm } from "../core/noble.ts";

export const sha3_256 = defineNobleAlgorithm({
  name: "sha3-256",
  label: "SHA3-256",
  description:
    "SHA-3 (Keccak) 256-bit hash, the NIST standard with a different internal structure from SHA-2",
  family: "cryptographic",
  hashFn,
  digestLength: 32,
  securityNote: "256-bit security level, sponge construction",
});
