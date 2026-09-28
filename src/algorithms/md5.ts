import { NodeHash } from "../core/node-hash.ts";

export class Md5 extends NodeHash {
  static readonly key = "md5";
  protected readonly algorithm = "md5";
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
