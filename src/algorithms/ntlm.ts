import { HashError } from "../core/errors.ts";
import { FixedHash } from "../core/fixed-hash.ts";
import { md4 } from "../core/md4.ts";

/** Reads the input as text, BOM included, and refuses bytes that are not UTF-8. */
const UTF8 = /* @__PURE__ */ new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });

export class Ntlm extends FixedHash {
  static readonly key = "ntlm";
  protected readonly about = {
    label: "NTLM",
    description:
      "NT hash of a Windows password: MD4 of the password in UTF-16LE, the hash NTLM and pass-the-hash use",
    family: "MD",
    category: "legacy",
    digestLength: 16,
    securityNote:
      "BROKEN as a password hash: no salt and no cost, so one table cracks every account with the same password",
  } as const;

  /**
   * Computes MD4 of the text in UTF-16LE, a code point past U+FFFF as its surrogate pair.
   *
   * @param bytes - The password as UTF-8.
   * @returns {Uint8Array} The 16-byte NT hash.
   */
  protected digest(bytes: Uint8Array): Uint8Array {
    let text: string;
    try {
      text = UTF8.decode(bytes);
    } catch {
      throw new HashError("ntlm hashes text, and the input is not valid UTF-8");
    }
    const utf16 = new Uint8Array(text.length * 2);
    let offset = 0;
    for (const character of text) {
      let unit = character.codePointAt(0)!;
      if (unit > 0xffff) {
        const high = 0xd800 | ((unit - 0x10000) >> 10);
        utf16[offset++] = high;
        utf16[offset++] = high >>> 8;
        unit = 0xdc00 | (unit & 0x3ff);
      }
      utf16[offset++] = unit;
      utf16[offset++] = unit >>> 8;
    }
    return md4(utf16);
  }
}
