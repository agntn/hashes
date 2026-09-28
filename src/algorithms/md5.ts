import { md5 as hashFn } from "@noble/hashes/legacy.js";
import { defineNobleAlgorithm } from "../core/noble.ts";

export const md5 = defineNobleAlgorithm({
  name: "md5",
  label: "MD5",
  description: "MD5 128-bit hash, BROKEN for security, still used for checksums and fingerprinting",
  family: "legacy",
  hashFn,
  digestLength: 16,
  securityNote: "BROKEN: collision attacks known since 2004. Use only for non-security checksums.",
});
