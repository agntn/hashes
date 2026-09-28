import type { AlgorithmEntry } from "../core/types.ts";
import { blake2b } from "./blake2b.ts";
import { blake2s } from "./blake2s.ts";
import { blake3 } from "./blake3.ts";
import { crc32 } from "./crc32.ts";
import { fnv1a } from "./fnv1a.ts";
import { md5 } from "./md5.ts";
import { pbkdf2 } from "./pbkdf2.ts";
import { ripemd160 } from "./ripemd160.ts";
import { scrypt } from "./scrypt.ts";
import { sha1 } from "./sha1.ts";
import { sha256 } from "./sha256.ts";
import { sha384 } from "./sha384.ts";
import { sha512 } from "./sha512.ts";
import { sha3_256 } from "./sha3-256.ts";
import { sha3_512 } from "./sha3-512.ts";
import { xxhash } from "./xxhash.ts";

/**
 * Every algorithm the package ships, in the order of `builtinAlgorithms`. Not in this list, not in
 * the registry; a test compares it with the files in this folder.
 */
export const builtins: readonly AlgorithmEntry[] = [
  sha256,
  sha384,
  sha512,
  sha3_256,
  sha3_512,
  blake2b,
  blake2s,
  blake3,
  ripemd160,
  md5,
  sha1,
  crc32,
  xxhash,
  fnv1a,
  scrypt,
  pbkdf2,
];
