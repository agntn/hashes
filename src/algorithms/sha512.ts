import { sha512 as hashFn } from "@noble/hashes/sha2.js";
import { defineNobleAlgorithm } from "../core/noble.ts";

export const sha512 = defineNobleAlgorithm({
  name: "sha512",
  label: "SHA-512",
  description:
    "SHA-2 family 512-bit hash, the strongest SHA-2 variant, used for high-security applications",
  family: "cryptographic",
  hashFn,
  digestLength: 64,
  securityNote: "512-bit security level",
});
