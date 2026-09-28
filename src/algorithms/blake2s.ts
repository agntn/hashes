import { blake2s as hashFn } from "@noble/hashes/blake2.js";
import { defineNobleAlgorithm } from "../core/noble.ts";

export const blake2s = defineNobleAlgorithm({
  name: "blake2s",
  label: "BLAKE2s",
  description: "BLAKE2s 256-bit hash, optimized for 32-bit platforms, smaller state than BLAKE2b",
  family: "cryptographic",
  hashFn,
  digestLength: 32,
  securityNote: "Up to 256-bit security level",
});
