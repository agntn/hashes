import { sha1 as hashFn } from "@noble/hashes/legacy.js";
import { defineNobleAlgorithm } from "../core/noble.ts";

export const sha1 = defineNobleAlgorithm({
  name: "sha1",
  label: "SHA-1",
  description:
    "SHA-1 160-bit hash, BROKEN for security (SHAttered 2017), still used in Git and legacy systems",
  family: "legacy",
  hashFn,
  digestLength: 20,
  securityNote:
    "BROKEN: practical collision attack (SHAttered). Use only for legacy compatibility.",
});
