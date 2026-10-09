import { assertPositiveIntegers, resolveSalt, type SaltOptions } from "../core/digest.ts";
import { InvalidOptionError } from "../core/errors.ts";
import { evpBytesToKey } from "../core/evp.ts";
import type { Hasher } from "../core/hasher.ts";
import { Kdf, type Derivation } from "../core/kdf.ts";
import { Md5Hasher } from "../core/md5.ts";
import { Sha1Hasher } from "../core/sha1.ts";
import { Sha256Hasher } from "../core/sha2.ts";
import type { HashOptions } from "../core/types.ts";

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

export class EvpBytesToKey extends Kdf<EvpBytesToKeyOptions> {
  static readonly key = "evp-bytestokey";
  protected readonly about = {
    label: "EVP_BytesToKey",
    description:
      "OpenSSL's EVP_BytesToKey, the key and IV behind openssl enc without -pbkdf2 and CryptoJS's EvpKDF",
    family: "OpenSSL",
    category: "password",
    securityNote:
      "Weak: one fast hash per block, so a password falls to a GPU. Only for reading what OpenSSL or CryptoJS already wrote. Use scrypt or pbkdf2 for anything new.",
  } as const;
  protected override readonly options = [
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
  ] as const;

  /**
   * Derives the key and the IV after it from the password.
   *
   * @param bytes - The password's bytes.
   * @param options - Salt, hash, iterations and lengths.
   * @returns {Derivation} The key followed by the IV, with what it reports.
   */
  protected derive(bytes: Uint8Array, options?: Readonly<EvpBytesToKeyOptions>): Derivation {
    const { digest, create, iterations, keyLength, ivLength, salt } = parameters(options);
    const length = keyLength + ivLength;
    return {
      digest: evpBytesToKey(create, bytes, salt ?? new Uint8Array(0), iterations, length),
      reported: {
        digest,
        iterations,
        keyLength,
        ivLength,
        ...(salt === undefined ? {} : { salt: salt.toHex() }),
      },
    };
  }
}
