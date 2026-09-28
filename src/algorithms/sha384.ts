import { sha384 as hashFn } from "@noble/hashes/sha2.js";
import { defineNobleAlgorithm } from "../core/noble.ts";

export const sha384 = defineNobleAlgorithm({
  name: "sha384",
  label: "SHA-384",
  description:
    "SHA-2 family 384-bit hash, a truncated SHA-512 used in TLS and government applications",
  family: "cryptographic",
  hashFn,
  digestLength: 48,
  securityNote: "384-bit security level",
});
