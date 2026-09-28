import type { HashConstructor } from "../core/hash.ts";
import { Blake2b } from "./blake2b.ts";
import { Blake2s } from "./blake2s.ts";
import { Blake3 } from "./blake3.ts";
import { Crc32 } from "./crc32.ts";
import { Fnv1a } from "./fnv1a.ts";
import { Md5 } from "./md5.ts";
import { Pbkdf2 } from "./pbkdf2.ts";
import { Ripemd160 } from "./ripemd160.ts";
import { Scrypt } from "./scrypt.ts";
import { Sha1 } from "./sha1.ts";
import { Sha256 } from "./sha256.ts";
import { Sha3_256 } from "./sha3-256.ts";
import { Sha3_512 } from "./sha3-512.ts";
import { Sha384 } from "./sha384.ts";
import { Sha512 } from "./sha512.ts";
import { Xxhash } from "./xxhash.ts";

/**
 * Every algorithm class the package ships, in the order of `builtinAlgorithms`. Not in this list,
 * not in the registry; a test compares it with the files in this folder.
 */
export const builtins: readonly HashConstructor[] = [
  Sha256,
  Sha384,
  Sha512,
  Sha3_256,
  Sha3_512,
  Blake2b,
  Blake2s,
  Blake3,
  Ripemd160,
  Md5,
  Sha1,
  Crc32,
  Xxhash,
  Fnv1a,
  Scrypt,
  Pbkdf2,
];

export {
  Blake2b,
  Blake2s,
  Blake3,
  Crc32,
  Fnv1a,
  Md5,
  Pbkdf2,
  Ripemd160,
  Scrypt,
  Sha1,
  Sha256,
  Sha384,
  Sha3_256,
  Sha3_512,
  Sha512,
  Xxhash,
};
