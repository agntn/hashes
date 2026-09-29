import type { HashConstructor } from "../core/hash.ts";
import { Blake256 } from "./blake256.ts";
import { Blake2b } from "./blake2b.ts";
import { Blake2b224 } from "./blake2b-224.ts";
import { Blake2b256 } from "./blake2b-256.ts";
import { Blake2s } from "./blake2s.ts";
import { Blake3 } from "./blake3.ts";
import { Crc16Xmodem } from "./crc16-xmodem.ts";
import { Crc32 } from "./crc32.ts";
import { Fnv1a } from "./fnv1a.ts";
import { Hash160 } from "./hash160.ts";
import { Hash256 } from "./hash256.ts";
import { Keccak256 } from "./keccak256.ts";
import { Md5 } from "./md5.ts";
import { Pbkdf2 } from "./pbkdf2.ts";
import { Ripemd160 } from "./ripemd160.ts";
import { Scrypt } from "./scrypt.ts";
import { Sha0 } from "./sha0.ts";
import { Sha1 } from "./sha1.ts";
import { Sha256 } from "./sha256.ts";
import { Sha3_256 } from "./sha3-256.ts";
import { Sha3_512 } from "./sha3-512.ts";
import { Sha384 } from "./sha384.ts";
import { Sha512 } from "./sha512.ts";
import { Sha512Half } from "./sha512-half.ts";
import { Xxhash } from "./xxhash.ts";

/**
 * Every algorithm class the package ships, in the order of `builtinAlgorithms`. Not in this list,
 * not in the registry; a test compares it with the files in this folder.
 */
export const builtins: readonly HashConstructor[] = [
  Sha256,
  Sha384,
  Sha512,
  Sha512Half,
  Sha3_256,
  Sha3_512,
  Keccak256,
  Blake2b,
  Blake2b256,
  Blake2b224,
  Blake2s,
  Blake3,
  Blake256,
  Ripemd160,
  Hash160,
  Hash256,
  Md5,
  Sha1,
  Sha0,
  Crc32,
  Crc16Xmodem,
  Xxhash,
  Fnv1a,
  Scrypt,
  Pbkdf2,
];

export {
  Blake256,
  Blake2b,
  Blake2b224,
  Blake2b256,
  Blake2s,
  Blake3,
  Crc16Xmodem,
  Crc32,
  Fnv1a,
  Hash160,
  Hash256,
  Keccak256,
  Md5,
  Pbkdf2,
  Ripemd160,
  Scrypt,
  Sha0,
  Sha1,
  Sha256,
  Sha384,
  Sha3_256,
  Sha3_512,
  Sha512,
  Sha512Half,
  Xxhash,
};
