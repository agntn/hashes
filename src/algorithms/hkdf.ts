import {
  isInputList,
  assertOneRound,
  decodeInput,
  ENCODING_OPTION,
  encodeDigest,
  guarded,
  resolveSalt,
  toBytes,
  type SaltOptions,
} from "../core/digest.ts";
import { Hash } from "../core/hash.ts";
import { hkdf } from "../core/hmac.ts";
import type { AlgorithmInfo, HashInput, HashOptions, HashResult } from "../core/types.ts";
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

export class Hkdf extends Hash {
  static readonly key = "hkdf";

  /**
   * Describes the algorithm.
   *
   * @returns {AlgorithmInfo} Its metadata.
   */
  info(): AlgorithmInfo {
    return {
      name: this.key,
      label: "HKDF",
      description:
        "HKDF (RFC 5869), HMAC extract and expand for key material that is already strong",
      family: "HKDF",
      category: "cryptographic",
      hmac: false,
      options: [
        ENCODING_OPTION,
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
      ],
      securityNote:
        "Not for passwords: HKDF adds no cost, so a guessable input stays guessable. Use scrypt or pbkdf2 there.",
    };
  }

  /**
   * Derives a key from the input key material.
   *
   * @param input - Text or bytes, or a list of them.
   * @param options - Encoding, salt, info, digest and length.
   * @returns {HashResult | HashResult[]} The derived key, one per input for a list.
   */
  hash(input: HashInput, options?: Readonly<HkdfOptions>): HashResult;
  hash(inputs: readonly HashInput[], options?: Readonly<HkdfOptions>): HashResult[];
  hash(
    input: HashInput | readonly HashInput[],
    options?: Readonly<HkdfOptions>,
  ): HashResult | HashResult[] {
    if (isInputList(input)) return input.map((one) => this.hash(one, options));
    return guarded(this.key, () => {
      if (options?.key !== undefined) throw new Error(`${this.key} has no HMAC mode`);
      assertOneRound(options, `${this.key} sets its output with its own parameters`);
      const { digest, hash, keyLength, salt, info } = parameters(options);
      const raw = hkdf(
        () => hash.hasher(),
        toBytes(input),
        salt ?? new Uint8Array(0),
        info,
        keyLength,
      );
      return encodeDigest(raw, this.key, "hash", options?.encoding ?? "hex", {
        digest,
        keyLength,
        ...(salt === undefined ? {} : { salt: salt.toHex() }),
        ...(info.length === 0 ? {} : { info: info.toHex() }),
      });
    });
  }
}
