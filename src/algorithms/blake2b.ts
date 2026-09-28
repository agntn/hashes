import { blake2b as hashFn } from "@noble/hashes/blake2.js";
import { defineNobleAlgorithm } from "../core/noble.ts";

export const blake2b = defineNobleAlgorithm({
  name: "blake2b",
  label: "BLAKE2b",
  description:
    "BLAKE2b 512-bit hash, fast and secure, used by many modern protocols (Argon2, WireGuard)",
  family: "cryptographic",
  hashFn,
  digestLength: 64,
  securityNote: "Up to 512-bit security level",
});
