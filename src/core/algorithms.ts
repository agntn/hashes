import { HASH_CATEGORIES } from "../../packages/shared/tool-contract.ts";

/** Built-in algorithm names, in listing order. Not in this list, not in the registry. */
export const builtinAlgorithms = [
  // Cryptographic (SHA-2)
  "sha256",
  "sha384",
  "sha512",
  "sha512-half",
  // Cryptographic (SHA-3 and Keccak)
  "sha3-256",
  "sha3-512",
  "keccak256",
  // Cryptographic (BLAKE)
  "blake2b",
  "blake2b-256",
  "blake2b-224",
  "blake2s",
  "blake3",
  "blake256",
  // Cryptographic (RIPEMD and Bitcoin's compositions)
  "ripemd160",
  "hash160",
  "hash256",
  // Legacy
  "md5",
  "sha1",
  "sha0",
  // Non-cryptographic
  "crc32",
  "crc16-xmodem",
  "xxhash",
  "fnv1a",
  // Password/KDF
  "scrypt",
  "pbkdf2",
  "hkdf",
  "evp-bytestokey",
] as const;

export type BuiltinAlgorithm = (typeof builtinAlgorithms)[number];

/** Algorithm categories, in listing order. The tool contract owns the list, since the extensions read it without the library. */
export const hashCategories = HASH_CATEGORIES;
