import type { BinaryLike } from 'node:crypto'

/** Output encoding for hash digests. */
export type OutputEncoding = 'hex' | 'base64' | 'base64url' | 'binary'

/** Result of a hash operation. */
export interface HashResult {
  /** The hash digest in the requested encoding. */
  digest: string | Uint8Array
  /** Name of the algorithm that produced this result. */
  algorithm: string
  /** Operation performed. */
  operation: 'hash' | 'hmac'
  /** Output encoding used. */
  encoding: OutputEncoding
  /** Byte length of the raw digest. */
  digestLength: number
  /** Options used (encoding, key, rounds, etc.). */
  options: Record<string, unknown>
}

/** Options for hash operations. */
export interface HashOptions {
  /** Output encoding. Default: 'hex'. */
  encoding?: OutputEncoding
  /** HMAC key — enables HMAC mode when set. */
  key?: string | Uint8Array
}

/** Algorithm family classification. */
export type HashFamily =
  | 'cryptographic'     // sha256, sha512, blake2b, blake3, sha3-*
  | 'legacy'            // md5, sha1 — not collision-resistant but still useful for checksums
  | 'non-cryptographic' // crc32, xxhash, fnv1a — fast, not security-grade
  | 'password'          // scrypt, pbkdf2 — key derivation / password hashing

/** Option descriptor for CLI/docs. */
export interface HashOption {
  name: string
  type: 'number' | 'string' | 'boolean'
  required: boolean
  default?: number | string | boolean
  description: string
}

/** Metadata about a hash algorithm. */
export interface AlgorithmInfo {
  /** Unique algorithm name. */
  name: string
  /** Human-readable label. */
  label: string
  /** One-line description. */
  description: string
  /** Algorithm family. */
  family: HashFamily
  /** Raw digest byte length (undefined for variable-length like SHAKE). */
  digestLength?: number
  /** Whether HMAC mode is supported. */
  hmac: boolean
  /** Self-describing options. */
  options: HashOption[]
  /** Key-space or security level note. */
  securityNote?: string
  /** External dependency (undefined = Node built-in). */
  dependency?: string
}

/** A hash algorithm provider. */
export interface HashAlgorithm {
  /** Algorithm name. */
  name(): string
  /** Algorithm metadata. */
  info(): AlgorithmInfo
  /** Compute hash (or HMAC) of input. */
  hash(input: BinaryLike | string, options?: HashOptions): HashResult
}

/** Factory function to create a hash algorithm instance. */
export type HashAlgorithmFactory = () => HashAlgorithm
