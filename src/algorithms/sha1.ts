import { NodeHash } from "../core/node-hash.ts";

export class Sha1 extends NodeHash {
  static readonly key = "sha1";
  protected readonly algorithm = "sha1";
  protected readonly about = {
    label: "SHA-1",
    description:
      "SHA-1 160-bit hash, BROKEN for security (SHAttered 2017), still used in Git and legacy systems",
    family: "legacy",
    digestLength: 20,
    securityNote:
      "BROKEN: practical collision attack (SHAttered). Use only for legacy compatibility.",
  } as const;
}
