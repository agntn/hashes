import { ripemd160 as hashFn } from "@noble/hashes/legacy.js";
import { defineNobleAlgorithm } from "../core/noble.ts";

export const ripemd160 = defineNobleAlgorithm({
  name: "ripemd160",
  label: "RIPEMD-160",
  description:
    "RIPEMD-160 160-bit hash, used in Bitcoin address derivation (Hash160 = RIPEMD160(SHA256(x)))",
  family: "cryptographic",
  hashFn,
  digestLength: 20,
  securityNote: "160-bit security level, used in Bitcoin",
});
