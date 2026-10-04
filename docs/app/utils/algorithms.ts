import {
  builtinAlgorithms,
  create,
  hashCategories,
  type AlgorithmInfo,
  type BuiltinAlgorithm,
  type HashCategory,
} from "@agntn/hashes";

const CATEGORY_LABELS: Record<HashCategory, string> = {
  cryptographic: "Cryptographic",
  legacy: "Legacy",
  "non-cryptographic": "Non-cryptographic",
  password: "Password",
};

/** Categories in listing order, with the label a page shows. The keys come from the library. */
export const CATEGORIES: ReadonlyArray<{ key: HashCategory; label: string }> = hashCategories.map(
  (key) => ({ key, label: CATEGORY_LABELS[key] }),
);

/** An icon, a one-liner and who runs it, per algorithm. Everything else comes from `info()`. */
const PRESENTATION: Record<BuiltinAlgorithm, { icon: string; blurb: string; usedBy?: string }> = {
  sha256: { icon: "i-lucide-hash", blurb: "The default. Certificates, signatures, Bitcoin" },
  sha384: { icon: "i-lucide-hash", blurb: "SHA-512 with other start values, cut to 48 bytes" },
  sha512: { icon: "i-lucide-hash", blurb: "The widest SHA-2, 64-bit words all the way" },
  sha224: { icon: "i-lucide-hash", blurb: "SHA-256 with other start values, cut to 28 bytes" },
  "sha512-224": { icon: "i-lucide-hash", blurb: "SHA-512 doing SHA-224's job, faster on 64 bits" },
  "sha512-256": {
    icon: "i-token-algo",
    blurb: "SHA-512 from its own start values, cut to 32 bytes",
    usedBy: "Algorand",
  },
  "sha512-half": {
    icon: "i-token-xrp",
    blurb: "The first half of SHA-512, which is not SHA-512/256",
    usedBy: "XRP Ledger",
  },
  "sha3-256": { icon: "i-lucide-waves", blurb: "NIST's sponge, nothing in common with SHA-2" },
  "sha3-512": { icon: "i-lucide-waves", blurb: "The sponge at 512 bits" },
  keccak256: {
    icon: "i-token-eth",
    blurb: "SHA-3 before NIST changed one padding byte",
    usedBy: "Ethereum, Tron, Monero",
  },
  blake2b: { icon: "i-lucide-shuffle", blurb: "Fast, unbroken, and what Argon2 runs on" },
  "blake2b-256": {
    icon: "i-token-sui",
    blurb: "BLAKE2b at 32 bytes, not half of the 64",
    usedBy: "Sui, Cardano",
  },
  "blake2b-224": {
    icon: "i-token-ada",
    blurb: "BLAKE2b at 28 bytes, for keys and scripts",
    usedBy: "Cardano",
  },
  blake2s: { icon: "i-lucide-shuffle", blurb: "BLAKE2 for 32-bit machines" },
  blake3: { icon: "i-lucide-zap", blurb: "A Merkle tree of chunks, absurdly fast" },
  blake256: {
    icon: "i-token-dcr",
    blurb: "The original BLAKE, the SHA-3 finalist",
    usedBy: "Decred",
  },
  ripemd160: {
    icon: "i-lucide-fingerprint",
    blurb: "160 bits from 1996, alive thanks to Bitcoin",
    usedBy: "Bitcoin",
  },
  ripemd320: {
    icon: "i-lucide-fingerprint",
    blurb: "RIPEMD-160 at 40 bytes, and not a bit stronger",
  },
  hash160: {
    icon: "i-token-btc",
    blurb: "RIPEMD-160 of SHA-256, a public key becomes an address",
    usedBy: "Bitcoin, Litecoin, Dogecoin, Dash, Zcash, XRP Ledger",
  },
  hash256: {
    icon: "i-token-btc",
    blurb: "SHA-256 twice, every txid and block hash",
    usedBy: "Bitcoin",
  },
  md5: { icon: "i-lucide-shield-alert", blurb: "Broken since 2004, still on every download page" },
  md4: { icon: "i-lucide-shield-alert", blurb: "MD5's older sibling, broken before MD5 was" },
  ntlm: {
    icon: "i-lucide-monitor",
    blurb: "MD4 of a password in UTF-16LE, no salt at all",
    usedBy: "Windows",
  },
  sha1: { icon: "i-lucide-shield-alert", blurb: "Broken since SHAttered, still inside Git" },
  sha0: { icon: "i-lucide-shield-alert", blurb: "SHA-1 minus one rotation, replaced in 1995" },
  ripemd128: { icon: "i-lucide-fingerprint", blurb: "Four rounds and 16 bytes, too short today" },
  ripemd256: {
    icon: "i-lucide-fingerprint",
    blurb: "RIPEMD-128 at 32 bytes, and not a bit stronger",
  },
  crc32: { icon: "i-lucide-file-digit", blurb: "The checksum in every ZIP, PNG, gzip and bzip2" },
  crc64: { icon: "i-lucide-file-digit", blurb: "Eight bytes after every xz block" },
  crc24: { icon: "i-lucide-mail-check", blurb: "Four base64 characters after the = in PGP armor" },
  "crc16-xmodem": {
    icon: "i-token-xlm",
    blurb: "Two bytes that close an address",
    usedBy: "Stellar, TON",
  },
  adler32: { icon: "i-lucide-sigma", blurb: "Two sums mod 65521 that close a zlib stream" },
  xxhash: { icon: "i-lucide-gauge", blurb: "XXH64 or XXH32, for hash tables and nothing secret" },
  fnv1a: { icon: "i-lucide-binary", blurb: "XOR, multiply, repeat. 64 bits of it" },
  scrypt: { icon: "i-lucide-hourglass", blurb: "Slow on purpose and hungry for memory" },
  pbkdf2: { icon: "i-lucide-key-round", blurb: "HMAC a few hundred thousand times" },
  hkdf: { icon: "i-lucide-split", blurb: "One strong secret, as many keys as the protocol needs" },
  "evp-bytestokey": { icon: "i-lucide-lock-keyhole-open", blurb: "Key and IV from a passphrase, the openssl enc way" },
  argon2id: { icon: "i-lucide-memory-stick", blurb: "The Argon2 that RFC 9106 tells you to pick" },
  argon2i: { icon: "i-lucide-eye-off", blurb: "Argon2 whose reads never depend on the password" },
  argon2d: { icon: "i-lucide-pickaxe", blurb: "Argon2 whose reads follow the data, fit for proof of work" },
  bcrypt: { icon: "i-lucide-fish", blurb: "Blowfish's key setup, run a few thousand times on purpose" },
};

export interface AlgorithmEntry {
  slug: BuiltinAlgorithm;
  to: string;
  icon: string;
  blurb: string;
  usedBy?: string;
  info: AlgorithmInfo;
}

/** The built-in algorithms in listing order, with their live metadata. */
export const ALGORITHMS: readonly AlgorithmEntry[] = builtinAlgorithms.map((slug) => ({
  slug,
  to: `/algorithms/${slug}`,
  ...PRESENTATION[slug],
  info: create(slug).info(),
}));

/**
 * One algorithm by its registry key.
 *
 * @param {string} slug - A built-in key.
 * @returns {AlgorithmEntry | undefined} Undefined for a key the site doesn't ship.
 */
export function algorithmEntry(slug: string): AlgorithmEntry | undefined {
  return ALGORITHMS.find((algorithm) => algorithm.slug === slug);
}

/** The families of the built-ins in listing order, as `info().family` spells them. */
export const FAMILIES: readonly string[] = [...new Set(ALGORITHMS.map((algorithm) => algorithm.info.family))];

/**
 * The label a page shows for a category.
 *
 * @param {HashCategory} category - A category as `info().category` reports it.
 * @returns {string} Its label.
 */
export function categoryLabel(category: HashCategory): string {
  return CATEGORY_LABELS[category];
}

/**
 * How many built-ins the library files under one category.
 *
 * @param {HashCategory} category - A category as `info().category` reports it.
 * @returns {number} The count in the registry.
 */
export function categorySize(category: HashCategory): number {
  return ALGORITHMS.filter((algorithm) => algorithm.info.category === category).length;
}

/** The built-ins that take a key, counted from `info().hmac`. */
export const HMAC_COUNT = ALGORITHMS.filter((algorithm) => algorithm.info.hmac).length;

/**
 * The digest size in bits, or `variable` for a KDF, where the caller picks it.
 *
 * @param {AlgorithmInfo} info - The algorithm's metadata.
 * @returns {string} `256-bit` or `variable`.
 */
export function digestBits(info: AlgorithmInfo): string {
  return info.digestLength === undefined ? "variable" : `${info.digestLength * 8}-bit`;
}

/**
 * One algorithm's place in the registry, 1-based, the way an ID bar numbers it.
 *
 * @param {string} slug - A built-in key.
 * @returns {number} Its position in `builtinAlgorithms`.
 */
export function registryPosition(slug: string): number {
  return ALGORITHMS.findIndex((algorithm) => algorithm.slug === slug) + 1;
}

/**
 * The options a tool call passes as `salt` or `parameters`: all but encoding and key.
 *
 * @param {AlgorithmInfo} info - The algorithm's metadata.
 * @returns {AlgorithmInfo["options"]} Salt, seed, costs and rounds, in declared order.
 */
export function callOptions(info: AlgorithmInfo): AlgorithmInfo["options"] {
  return info.options.filter((option) => option.name !== "encoding" && option.name !== "key");
}

/** Options every fixed-length digest takes, so they tell no algorithm apart from another. */
const SHARED_OPTIONS = new Set(["rounds", "chain"]);

/**
 * The options that set an algorithm apart, without the rounds every fixed-length digest takes.
 *
 * @param {AlgorithmInfo} info - The algorithm's metadata.
 * @returns {AlgorithmInfo["options"]} Salt, seed and cost parameters, in declared order.
 */
export function ownOptions(info: AlgorithmInfo): AlgorithmInfo["options"] {
  return callOptions(info).filter((option) => !SHARED_OPTIONS.has(option.name));
}

/**
 * The security note as `info()` states it, cut to its first clause, so a roster cell shows
 * `128-bit collision resistance` and a tooltip carries the whole note.
 *
 * @param {AlgorithmInfo} info - The algorithm's metadata.
 * @returns {{ short: string; full: string } | undefined} Undefined when the algorithm states none.
 */
export function securityParts(info: AlgorithmInfo): { short: string; full: string } | undefined {
  if (!info.securityNote) return undefined;
  const short = info.securityNote.split(/[.,](?=\s)/u)[0]!.replace(/\.$/u, "");
  return { short, full: info.securityNote };
}

/** `saltsalt` at 1 MiB and 2 passes, since the real 64 MiB at 3 passes takes a second in a tab. */
const ARGON2_SAMPLE = { salt: "73616c7473616c74", memory: 1024, iterations: 2, parallelism: 1 };

/**
 * Options an algorithm page hashes its sample with. The KDFs get a fixed salt and a small cost,
 * so the page stays reproducible and doesn't spend seconds on 600000 PBKDF2 rounds.
 */
export const SAMPLE_OPTIONS: Partial<Record<BuiltinAlgorithm, Record<string, string | number>>> = {
  scrypt: { salt: "73616c74", N: 1024 },
  pbkdf2: { salt: "73616c74", iterations: 1000 },
  "evp-bytestokey": { salt: "0102030405060708" },
  argon2id: ARGON2_SAMPLE,
  argon2i: ARGON2_SAMPLE,
  argon2d: ARGON2_SAMPLE,
  bcrypt: { salt: "73616c7473616c7473616c7473616c74", cost: 4 },
};
