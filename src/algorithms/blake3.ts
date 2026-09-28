import { blake3 as hashFn } from "@noble/hashes/blake3.js";
import { defineNobleAlgorithm } from "../core/noble.ts";

export const blake3 = defineNobleAlgorithm({
  name: "blake3",
  label: "BLAKE3",
  description: "BLAKE3, an extremely fast cryptographic hash, parallelizable, 256-bit output",
  family: "cryptographic",
  hashFn,
  digestLength: 32,
  hmac: false,
  securityNote: "256-bit security level, Merkle tree structure for parallelism",
});
