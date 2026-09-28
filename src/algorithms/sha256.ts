import { sha256 as hashFn } from "@noble/hashes/sha2.js";
import { defineNobleAlgorithm } from "../core/noble.ts";

export const sha256 = defineNobleAlgorithm({
  name: "sha256",
  label: "SHA-256",
  description:
    "SHA-2 family 256-bit hash, widely used for digital signatures, certificates, and integrity checks",
  family: "cryptographic",
  hashFn,
  digestLength: 32,
  securityNote: "256-bit security level",
});
