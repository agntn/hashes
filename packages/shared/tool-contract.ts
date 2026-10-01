/**
 * The contract of the hash tools: bounds, allowed values and descriptions. The schemas declare it,
 * the executors in `src/tool-operations.ts` enforce it again, since a host may skip validation.
 *
 * Nothing here imports a dependency: the library and the docs site read it too.
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
/** Longest text parameter. HKDF info for a TLS 1.3 label runs past 64 hex digits. */
export const MAX_PARAMETER_LENGTH = 1_024;

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
  ivLength: 1_024,
  rounds: 1_000_000,
  memory: 262_144,
};
/** Parameters that may be 0 under their tool limit: no IV for a cipher without one. */
export const ZERO_PARAMETERS: readonly string[] = ["ivLength"];
/** Largest block table a scrypt call may fill, 128 * r * N bytes. */
export const MAX_SCRYPT_MEMORY = 256 * 1024 * 1024;
/** Most KiB an Argon2 call may fill over all its passes, memory * iterations: about 5 s. */
export const MAX_ARGON2_WORK = 1_048_576;

export const TEXT_ENCODINGS = ["hex", "base64", "base64url"] as const;
export const INPUT_ENCODINGS = ["utf8", "hex", "base64"] as const;
export const HASH_CATEGORIES = [
  "cryptographic",
  "legacy",
  "non-cryptographic",
  "password",
] as const;
export const BUILTIN_FAMILIES =
  "SHA, Keccak, BLAKE, RIPEMD, MD, CRC, xxHash, FNV, scrypt, PBKDF, HKDF, OpenSSL, Argon2";
export const BUILTIN_ALGORITHMS =
  "sha256, sha384, sha512, sha224, sha512-224, sha512-256, sha512-half, sha3-256, sha3-512, keccak256, blake2b, blake2b-256, blake2b-224, blake2s, blake3, blake256, ripemd160, ripemd320, hash160, hash256, md5, md4, ntlm, sha1, sha0, ripemd128, ripemd256, crc32, crc16-xmodem, xxhash, fnv1a, scrypt, pbkdf2, hkdf, evp-bytestokey, argon2id, argon2i, argon2d";
export const HMAC_ALGORITHMS =
  "sha256, sha384, sha512, sha224, sha512-224, sha512-256, sha3-256, sha3-512, keccak256, blake2b, blake2s, ripemd160, ripemd320, md5, md4, sha1, sha0, ripemd128, ripemd256";

/** What each tool does, the same text on every surface. */
export const TOOL_DESCRIPTIONS = {
  hashes_compute:
    "Hash text or bytes with any registered algorithm. The answer is the digest, then the algorithm, encoding, length and, for a KDF, the salt and parameters needed to reproduce it.",
  hashes_hmac_compute:
    "Compute an HMAC of text or bytes with a key, using an algorithm that has an HMAC mode.",
  hashes_verify:
    "Hash text or bytes and compare the digest with an expected one in constant time. Answers MATCH or MISMATCH with both digests. scrypt, pbkdf2 and argon2 need the salt the expected digest was made with.",
  hashes_algorithms:
    "List the registered algorithms with family, category, digest size and HMAC support, or describe one algorithm with its options.",
} as const;

/** What each tool is called in a status line or a tool list. */
export const TOOL_TITLES = {
  hashes_compute: "Hash Compute",
  hashes_hmac_compute: "Hash HMAC",
  hashes_verify: "Hash Verify",
  hashes_algorithms: "Hash Algorithms",
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
    salt: "KDFs only (scrypt, pbkdf2, argon2id, argon2i, argon2d, hkdf, evp-bytestokey): salt in hex. Omitted, scrypt, pbkdf2 and argon2 draw a random 32-byte salt and the answer names it, hashes_verify needs it. hkdf reads a missing salt as zeros, evp-bytestokey as none. argon2 takes at least 8 bytes, evp-bytestokey exactly 8",
    expected:
      "Expected digest. Hex ignores case and takes no 0x prefix, base64 and base64url keep case",
    expectedEncoding: "Encoding of the expected digest (default hex)",
    verifySalt:
      "KDFs only (scrypt, pbkdf2, argon2id, argon2i, argon2d, hkdf, evp-bytestokey): the salt in hex the expected digest was made with, required for scrypt, pbkdf2 and argon2",
    parameters:
      "Options the algorithm takes besides encoding, key and salt, as hashes_algorithms lists them: rounds and chain (bytes or hex) for every algorithm but the KDFs, seed for xxhash, N, r, p and keyLength for scrypt, iterations, digest and keyLength for pbkdf2, info (hex), digest and keyLength for hkdf, digest, iterations, keyLength and ivLength for evp-bytestokey, memory (KiB), iterations, parallelism, keyLength, secret (hex) and associatedData (hex) for argon2id, argon2i and argon2d",
    category: "Category to list. Omit to list every category",
    family: `Family to list, case-insensitive: ${BUILTIN_FAMILIES}. Omit to list every family`,
    describe: "Registered algorithm to describe with its options. Omit to list",
  } as const;
}

/** What each argument means, the same text in every schema that declares it. */
export const PARAMETER_DESCRIPTIONS = /* @__PURE__ */ parameterDescriptions();
