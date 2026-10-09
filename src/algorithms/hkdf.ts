import { decodeInput, resolveSalt, toBytes, type SaltOptions } from "../core/digest.ts";
import { hkdf } from "../core/hmac.ts";
import { Kdf, type Derivation } from "../core/kdf.ts";
import type { HashOptions } from "../core/types.ts";
import { kdfDigests, kdfHash } from "./pbkdf2.ts";

/** Options HKDF takes besides the encoding. */
export interface HkdfOptions extends HashOptions, SaltOptions {
  /** Context bytes, hex in a string. Default: none. */
  info?: string | Uint8Array;
  /** Hash under HMAC: sha256, sha384, sha512, sha3-256, sha3-512. Default: sha256. */
  digest?: string;
  /** Output key length in bytes, at most 255 digests. Default: 32. */
  keyLength?: number;
}

/**
 * Reads the HKDF options with their defaults. A missing salt stays undefined, not random.
 *
 * @param options - The HKDF options.
 * @returns {{ digest: string, hash: BlockHash, keyLength: number, salt: Uint8Array | undefined, info: Uint8Array }} The parameters.
 */
function parameters(options?: Readonly<HkdfOptions>) {
  const { digest = "sha256", keyLength = 32, info = "" } = options ?? {};
  return {
    digest,
    hash: kdfHash(digest),
    keyLength,
    salt: options?.salt === undefined ? undefined : resolveSalt(options),
    info: typeof info === "string" ? toBytes(decodeInput(info, "hex", "info")) : info,
  };
}

export class Hkdf extends Kdf<HkdfOptions> {
  static readonly key = "hkdf";
  protected readonly about = {
    label: "HKDF",
    description: "HKDF (RFC 5869), HMAC extract and expand for key material that is already strong",
    family: "HKDF",
    category: "cryptographic",
    securityNote:
      "Not for passwords: HKDF adds no cost, so a guessable input stays guessable. Use scrypt or pbkdf2 there.",
  } as const;
  protected override readonly options = [
    {
      name: "salt",
      type: "string",
      required: false,
      description: "Salt in hex; zeros when omitted",
    },
    {
      name: "info",
      type: "string",
      required: false,
      default: "",
      description: "Context in hex that binds the key to its use",
    },
    {
      name: "digest",
      type: "string",
      required: false,
      default: "sha256",
      description: `Underlying hash: ${kdfDigests()}`,
    },
    {
      name: "keyLength",
      type: "number",
      required: false,
      default: 32,
      description: "Output key length in bytes, at most 255 digests",
    },
  ] as const;
  protected override readonly roundsNote = "sets its output with its own parameters";

  /**
   * Derives a key from the input key material, the salt zeros when missing.
   *
   * @param bytes - The input key material.
   * @param options - Salt, info, hash and length.
   * @returns {Derivation} The key, with the salt and info it reports when given.
   */
  protected derive(bytes: Uint8Array, options?: Readonly<HkdfOptions>): Derivation {
    const { digest, hash, keyLength, salt, info } = parameters(options);
    return {
      digest: hkdf(() => hash.hasher(), bytes, salt ?? new Uint8Array(0), info, keyLength),
      reported: {
        digest,
        keyLength,
        ...(salt === undefined ? {} : { salt: salt.toHex() }),
        ...(info.length === 0 ? {} : { info: info.toHex() }),
      },
    };
  }
}
