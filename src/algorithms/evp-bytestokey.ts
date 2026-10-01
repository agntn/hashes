import {
  assertOneRound,
  assertPositiveIntegers,
  ENCODING_OPTION,
  encodeDigest,
  guarded,
  resolveSalt,
  toBytes,
  type SaltOptions,
} from "../core/digest.ts";
import { InvalidOptionError } from "../core/errors.ts";
import { Hash } from "../core/hash.ts";
import type { Hasher } from "../core/hasher.ts";
import { Md5Hasher } from "../core/md5.ts";
import { Sha1Hasher } from "../core/sha1.ts";
import { Sha256Hasher } from "../core/sha2.ts";
import type { AlgorithmInfo, HashInput, HashOptions, HashResult } from "../core/types.ts";

/** Hashes `openssl enc -md` takes here, by their registry names. */
const HASHERS: Readonly<Record<string, new () => Hasher>> = {
  md5: Md5Hasher,
  sha1: Sha1Hasher,
  sha256: Sha256Hasher,
};

/** The salt length OpenSSL writes after `Salted__` (PKCS5_SALT_LEN). */
const SALT_LENGTH = 8;

/** Options EVP_BytesToKey takes besides the encoding. */
export interface EvpBytesToKeyOptions extends HashOptions, SaltOptions {
  /** Hash per block: md5, sha1, sha256. Default: md5. */
  digest?: string;
  /** Hash passes per block. Default: 1. */
  iterations?: number;
  /** Key bytes, the first part of the digest. Default: 32. */
  keyLength?: number;
  /** IV bytes after the key, 0 for none. Default: 16. */
  ivLength?: number;
}

/**
 * Reads the EVP_BytesToKey options with their defaults. A missing salt stays empty, not random.
 *
 * @param options - The EVP_BytesToKey options.
 * @returns {{ digest: string, create: () => Hasher, iterations: number, keyLength: number, ivLength: number, salt: Uint8Array | undefined }} The parameters.
 */
function parameters(options?: Readonly<EvpBytesToKeyOptions>) {
  const { digest = "md5", iterations = 1, keyLength = 32, ivLength = 16 } = options ?? {};
  if (!Object.hasOwn(HASHERS, digest)) {
    throw new InvalidOptionError("digest", digest, `use one of ${Object.keys(HASHERS).join(", ")}`);
  }
  assertPositiveIntegers({ iterations, keyLength });
  if (ivLength !== 0) assertPositiveIntegers({ ivLength });
  const Hasher = HASHERS[digest]!;
  const salt = saltOf(options);
  return { digest, create: () => new Hasher(), iterations, keyLength, ivLength, salt };
}

/**
 * Reads the salt, which OpenSSL takes as exactly 8 bytes or not at all.
 *
 * @param options - The EVP_BytesToKey options.
 * @returns {Uint8Array | undefined} The salt, or undefined without one.
 */
function saltOf(options?: Readonly<SaltOptions>): Uint8Array | undefined {
  if (options?.salt === undefined) return undefined;
  const salt = resolveSalt(options);
  if (salt.length !== SALT_LENGTH) {
    throw new InvalidOptionError("salt", salt.toHex(), `must be ${SALT_LENGTH} bytes`);
  }
  return salt;
}

/**
 * Derives bytes the way OpenSSL's EVP_BytesToKey does: each block hashes the one before it, the
 * password and the salt, then hashes itself again until it has had `iterations` passes.
 *
 * @param create - Creates a fresh hasher of the digest.
 * @param password - The password.
 * @param salt - The salt, empty for none.
 * @param iterations - Hash passes per block.
 * @param length - Bytes to derive.
 * @returns {Uint8Array} The derived bytes.
 */
function evpBytesToKey(
  create: () => Hasher,
  password: Uint8Array,
  salt: Uint8Array,
  iterations: number,
  length: number,
): Uint8Array {
  const fresh = create();
  const hasher = create();
  const block = new Uint8Array(hasher.outputLength);
  const out = new Uint8Array(length);
  for (let offset = 0; offset < length; offset += block.length) {
    hasher.load(fresh);
    if (offset > 0) hasher.update(block);
    hasher.update(password).update(salt).digestInto(block);
    for (let i = 1; i < iterations; i++) hasher.load(fresh).update(block).digestInto(block);
    out.set(block.subarray(0, Math.min(block.length, length - offset)), offset);
  }
  return out;
}

export class EvpBytesToKey extends Hash {
  static readonly key = "evp-bytestokey";

  /**
   * Describes the algorithm.
   *
   * @returns {AlgorithmInfo} Its metadata.
   */
  info(): AlgorithmInfo {
    return {
      name: this.key,
      label: "EVP_BytesToKey",
      description:
        "OpenSSL's EVP_BytesToKey, the key and IV behind openssl enc without -pbkdf2 and CryptoJS's EvpKDF",
      family: "OpenSSL",
      category: "password",
      hmac: false,
      options: [
        ENCODING_OPTION,
        {
          name: "salt",
          type: "string",
          required: false,
          description: `Salt in hex, ${SALT_LENGTH} bytes; none when omitted`,
        },
        {
          name: "digest",
          type: "string",
          required: false,
          default: "md5",
          description: `Hash per block: ${Object.keys(HASHERS).join(", ")}. openssl enc uses sha256 since 1.1.0`,
        },
        {
          name: "iterations",
          type: "number",
          required: false,
          default: 1,
          description: "Hash passes per block",
        },
        {
          name: "keyLength",
          type: "number",
          required: false,
          default: 32,
          description: "Key bytes, the first part of the digest",
        },
        {
          name: "ivLength",
          type: "number",
          required: false,
          default: 16,
          description: "IV bytes after the key, 0 for none",
        },
      ],
      securityNote:
        "Weak: one fast hash per block, so a password falls to a GPU. Only for reading what OpenSSL or CryptoJS already wrote. Use scrypt or pbkdf2 for anything new.",
    };
  }

  /**
   * Derives the key and the IV after it from the password.
   *
   * @param input - Text or bytes.
   * @param options - Encoding, salt, digest, iterations and lengths.
   * @returns {HashResult} The key followed by the IV.
   */
  hash(input: HashInput, options?: Readonly<EvpBytesToKeyOptions>): HashResult {
    return guarded(this.key, () => {
      if (options?.key !== undefined) throw new Error(`${this.key} has no HMAC mode`);
      assertOneRound(options, `${this.key} sets its cost with its own parameters`);
      const { digest, create, iterations, keyLength, ivLength, salt } = parameters(options);
      const raw = evpBytesToKey(
        create,
        toBytes(input),
        salt ?? new Uint8Array(0),
        iterations,
        keyLength + ivLength,
      );
      return encodeDigest(raw, this.key, "hash", options?.encoding ?? "hex", {
        digest,
        iterations,
        keyLength,
        ivLength,
        ...(salt === undefined ? {} : { salt: salt.toHex() }),
      });
    });
  }
}
