/** Built-in algorithm names — used for type-safe iteration. */
export const builtinAlgorithms = [
  // Cryptographic (SHA-2)
  'sha256',
  'sha384',
  'sha512',
  // Cryptographic (SHA-3)
  'sha3-256',
  'sha3-512',
  // Cryptographic (BLAKE)
  'blake2b',
  'blake2s',
  'blake3',
  // Cryptographic (other)
  'ripemd160',
  // Legacy
  'md5',
  'sha1',
  // Non-cryptographic
  'crc32',
  'xxhash',
  'fnv1a',
  // Password/KDF
  'scrypt',
  'pbkdf2',
] as const

export type BuiltinAlgorithm = (typeof builtinAlgorithms)[number]
