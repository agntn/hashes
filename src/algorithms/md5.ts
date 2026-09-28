import { md5 } from "@noble/hashes/legacy.js";
import { NobleHash } from "../core/noble.ts";

export class Md5 extends NobleHash {
  static readonly key = "md5";
  protected readonly hashFn = md5;
  protected readonly about = {
    label: "MD5",
    description:
      "MD5 128-bit hash, BROKEN for security, still used for checksums and fingerprinting",
    family: "legacy",
    digestLength: 16,
    securityNote:
      "BROKEN: collision attacks known since 2004. Use only for non-security checksums.",
  } as const;
}
