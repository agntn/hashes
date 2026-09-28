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

/** What each tool is called in a status line or a tool list. */
export const TOOL_TITLES = {
  hash_compute: "Hash Compute",
  hash_hmac: "Hash HMAC",
  hash_verify: "Hash Verify",
  hash_algorithms: "Hash Algorithms",
} as const;

/** What each argument means, the same text in every schema that declares it. */
export const PARAMETER_DESCRIPTIONS = {
  algorithm: `Algorithm name, case-insensitive: ${BUILTIN_ALGORITHMS}`,
  hmacAlgorithm: `Algorithm with an HMAC mode: ${HMAC_ALGORITHMS}`,
  input: "Text to hash, read as UTF-8",
  key: "HMAC key, read as UTF-8",
  encoding: "Digest encoding (default hex)",
  salt: "scrypt and pbkdf2 only: salt in hex. Omitted, a random 32-byte salt is drawn and the answer names it. hash_verify needs it",
  expected: "Expected digest. Hex ignores case, base64 and base64url do not",
  expectedEncoding: "Encoding of the expected digest (default hex)",
  verifySalt:
    "scrypt and pbkdf2 only, and required there: the salt in hex the expected digest was made with",
  family: "Family to list. Omit to list every family",
  describe: "Registered algorithm to describe with its options. Omit to list",
} as const;
