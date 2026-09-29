/** Output encoding for hash digests. */
export type OutputEncoding = "hex" | "base64" | "base64url" | "binary";

/** Text or bytes to hash. A string is read as UTF-8. */
export type HashInput = string | Uint8Array;

/** Result of a hash operation. */
export interface HashResult {
  /** The digest in the requested encoding; bytes for `binary`. */
  digest: string | Uint8Array;
  /** Name of the algorithm that produced this result. */
  algorithm: string;
  /** Operation performed. */
  operation: "hash" | "hmac";
  /** Output encoding used. */
  encoding: OutputEncoding;
  /** Byte length of the raw digest. */
  digestLength: number;
  /** Options the digest depends on (encoding, salt, cost parameters). */
  options: Record<string, unknown>;
}

/** Options for hash operations. */
export interface HashOptions {
  /** Output encoding. Default: `hex`. */
  encoding?: OutputEncoding;
  /** HMAC key; enables HMAC mode when set. */
  key?: HashInput;
}

/** What an algorithm is fit for, whatever family it comes from. */
export type HashCategory =
  /** sha256, sha512, blake2b, blake3, sha3-* */
  | "cryptographic"
  /** md5, sha1, sha0: not collision-resistant but still useful for checksums */
  | "legacy"
  /** crc32, xxhash, fnv1a: fast, not security-grade */
  | "non-cryptographic"
  /** scrypt, pbkdf2: key derivation and password hashing */
  | "password";

/** Option descriptor for the CLI and the tool descriptions. */
export interface HashOption {
  name: string;
  type: "number" | "string" | "boolean";
  required: boolean;
  default?: number | string | boolean;
  description: string;
}

/** Metadata about a hash algorithm. */
export interface AlgorithmInfo {
  /** Unique algorithm name. */
  name: string;
  /** Human-readable label. */
  label: string;
  /** One-line description. */
  description: string;
  /** Design lineage the algorithm belongs to, such as `SHA`, `BLAKE` or `CRC`. */
  family: string;
  /** What the algorithm is fit for: a digest that resists attack, a broken one, a checksum or a KDF. */
  category: HashCategory;
  /** Raw digest byte length; absent when the caller picks it, as for the KDFs. */
  digestLength?: number;
  /** Whether HMAC mode is supported. */
  hmac: boolean;
  /** Self-describing options. */
  options: HashOption[];
  /** Key-space or security level note. */
  securityNote?: string;
  /** Package a registered algorithm needs beyond this one; built-ins need none. */
  dependency?: string;
}
