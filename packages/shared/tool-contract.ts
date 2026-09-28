/**
 * The contract of the hash tools: bounds, allowed values and descriptions. The schemas declare it,
 * the executors in `src/tool-operations.ts` enforce it again, since a host may skip validation.
 *
 * It lives beside the extensions, not in `src`: the Pi and OMP extensions read it before the
 * library loads, and the package ships no `src`. Nothing here imports a dependency.
 */

/** Bounds on model-controlled work: a KDF runs its full cost on whatever input it gets. */
export const MAX_INPUT_LENGTH = 1_000_000;
export const MAX_KEY_LENGTH = 10_000;
export const MAX_ALGORITHM_LENGTH = 32;
export const MAX_EXPECTED_LENGTH = 1_024;
export const SALT_PATTERN = "^(?:[0-9A-Fa-f]{2}){1,256}$";
export const TEXT_ENCODINGS = ["hex", "base64", "base64url"] as const;
export const HASH_FAMILIES = ["cryptographic", "legacy", "non-cryptographic", "password"] as const;
export const BUILTIN_ALGORITHMS =
  "sha256, sha384, sha512, sha3-256, sha3-512, blake2b, blake2s, blake3, ripemd160, md5, sha1, crc32, xxhash, fnv1a, scrypt, pbkdf2";
export const HMAC_ALGORITHMS =
  "sha256, sha384, sha512, sha3-256, sha3-512, blake2b, blake2s, ripemd160, md5, sha1";

/** What each tool does, the same text on every surface. */
export const TOOL_DESCRIPTIONS = {
  hash_compute:
    "Hash text with any registered algorithm. The answer is the digest, then the algorithm, encoding, length and, for scrypt and pbkdf2, the salt and cost parameters needed to reproduce it.",
  hash_hmac: "Compute an HMAC of text with a key, using an algorithm that has an HMAC mode.",
  hash_verify:
    "Hash text and compare the digest with an expected one in constant time. Answers MATCH or MISMATCH with both digests. scrypt and pbkdf2 need the salt the expected digest was made with.",
  hash_algorithms:
    "List the registered algorithms with family, digest size and HMAC support, or describe one algorithm with its options.",
} as const;
