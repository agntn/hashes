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
export const MAX_FAMILY_LENGTH = 32;
export const MAX_EXPECTED_LENGTH = 1_024;
export const SALT_PATTERN = "^(?:[0-9A-Fa-f]{2}){1,256}$";
/** Most parameters a call may pass, and the pattern of their names. */
export const MAX_PARAMETERS = 8;
export const PARAMETER_NAME_PATTERN = "^[A-Za-z][A-Za-z0-9]{0,31}$";
export const MAX_PARAMETER_LENGTH = 64;

/**
 * Upper bounds on the cost parameters a model may choose. A caller of the library picks any cost;
 * a tool call is capped so one argument cannot pin the CPU or allocate gigabytes.
 */
export const PARAMETER_LIMITS: Readonly<Record<string, number>> = {
  N: 1_048_576,
  r: 32,
  p: 16,
  iterations: 10_000_000,
  keyLength: 1_024,
};
/** Most working memory a scrypt call may take, 128 * r * (N + p + 2) bytes. */
export const MAX_SCRYPT_MEMORY = 256 * 1024 * 1024;

export const TEXT_ENCODINGS = ["hex", "base64", "base64url"] as const;
export const INPUT_ENCODINGS = ["utf8", "hex", "base64"] as const;
export const HASH_CATEGORIES = [
  "cryptographic",
  "legacy",
  "non-cryptographic",
  "password",
] as const;
export const BUILTIN_FAMILIES = "SHA, Keccak, BLAKE, RIPEMD, MD, CRC, xxHash, FNV, scrypt, PBKDF";
export const BUILTIN_ALGORITHMS =
  "sha256, sha384, sha512, sha512-half, sha3-256, sha3-512, keccak256, blake2b, blake2b-256, blake2b-224, blake2s, blake3, blake256, ripemd160, hash160, hash256, md5, sha1, sha0, crc32, crc16-xmodem, xxhash, fnv1a, scrypt, pbkdf2";
export const HMAC_ALGORITHMS =
  "sha256, sha384, sha512, sha3-256, sha3-512, keccak256, blake2b, blake2s, ripemd160, md5, sha1, sha0";

/** What each tool does, the same text on every surface. */
export const TOOL_DESCRIPTIONS = {
  hash_compute:
    "Hash text or bytes with any registered algorithm. The answer is the digest, then the algorithm, encoding, length and, for scrypt and pbkdf2, the salt and cost parameters needed to reproduce it.",
  hash_hmac:
    "Compute an HMAC of text or bytes with a key, using an algorithm that has an HMAC mode.",
  hash_verify:
    "Hash text or bytes and compare the digest with an expected one in constant time. Answers MATCH or MISMATCH with both digests. scrypt and pbkdf2 need the salt the expected digest was made with.",
  hash_algorithms:
    "List the registered algorithms with family, category, digest size and HMAC support, or describe one algorithm with its options.",
} as const;

/** What each tool is called in a status line or a tool list. */
export const TOOL_TITLES = {
  hash_compute: "Hash Compute",
  hash_hmac: "Hash HMAC",
  hash_verify: "Hash Verify",
  hash_algorithms: "Hash Algorithms",
} as const;

/**
 * Builds the argument descriptions. Behind a pure call because esbuild keeps a module-level
 * template literal with a substitution, and with it this text, in a bundle that never reads it.
 *
 * @returns {Readonly<Record<string, string>>} The descriptions by argument name.
 */
function parameterDescriptions() {
  return {
    algorithm: `Algorithm name, case-insensitive: ${BUILTIN_ALGORITHMS}`,
    hmacAlgorithm: `Algorithm with an HMAC mode: ${HMAC_ALGORITHMS}`,
    input: "Input to hash, read as inputEncoding says",
    inputEncoding:
      "How to read input (default utf8). hex and base64 hash the bytes they spell, such as a public key or a raw transaction. hex takes no 0x prefix",
    key: "HMAC key, read as keyEncoding says",
    keyEncoding:
      "How to read key (default utf8). hex and base64 give a binary key, such as a BIP32 chain code. hex takes no 0x prefix",
    encoding: "Digest encoding (default hex)",
    salt: "scrypt and pbkdf2 only: salt in hex. Omitted, a random 32-byte salt is drawn and the answer names it. hash_verify needs it",
    expected: "Expected digest. Hex ignores case, base64 and base64url do not",
    expectedEncoding: "Encoding of the expected digest (default hex)",
    verifySalt:
      "scrypt and pbkdf2 only, and required there: the salt in hex the expected digest was made with",
    parameters:
      "Options the algorithm takes besides encoding, key and salt, as hash_algorithms lists them: seed for xxhash, N, r, p and keyLength for scrypt, iterations, digest and keyLength for pbkdf2",
    category: "Category to list. Omit to list every category",
    family: `Family to list, case-insensitive: ${BUILTIN_FAMILIES}. Omit to list every family`,
    describe: "Registered algorithm to describe with its options. Omit to list",
  } as const;
}

/** What each argument means, the same text in every schema that declares it. */
export const PARAMETER_DESCRIPTIONS = /* @__PURE__ */ parameterDescriptions();
