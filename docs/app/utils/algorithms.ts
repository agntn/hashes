import {
  builtinAlgorithms,
  create,
  hashFamilies,
  type AlgorithmInfo,
  type BuiltinAlgorithm,
  type HashFamily,
} from "@agntn/hashes";

const FAMILY_LABELS: Record<HashFamily, string> = {
  cryptographic: "Cryptographic",
  legacy: "Legacy",
  "non-cryptographic": "Non-cryptographic",
  password: "Password",
};

/** Families in listing order, with the label a page shows. The keys come from the library. */
export const FAMILIES: ReadonlyArray<{ key: HashFamily; label: string }> = hashFamilies.map(
  (key) => ({ key, label: FAMILY_LABELS[key] }),
);

/** An icon, a one-liner and who runs it, per algorithm. Everything else comes from `info()`. */
const PRESENTATION: Record<BuiltinAlgorithm, { icon: string; blurb: string; usedBy?: string }> = {
  sha256: { icon: "i-lucide-hash", blurb: "The default. Certificates, signatures, Bitcoin" },
  sha384: { icon: "i-lucide-hash", blurb: "SHA-512 with other start values, cut to 48 bytes" },
  sha512: { icon: "i-lucide-hash", blurb: "The widest SHA-2, 64-bit words all the way" },
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
  sha1: { icon: "i-lucide-shield-alert", blurb: "Broken since SHAttered, still inside Git" },
  sha0: { icon: "i-lucide-shield-alert", blurb: "SHA-1 minus one rotation, replaced in 1995" },
  crc32: { icon: "i-lucide-file-digit", blurb: "The checksum in every ZIP, PNG and gzip" },
  "crc16-xmodem": {
    icon: "i-token-xlm",
    blurb: "Two bytes that close an address",
    usedBy: "Stellar, TON",
  },
  xxhash: { icon: "i-lucide-gauge", blurb: "XXH64, for hash tables and nothing secret" },
  fnv1a: { icon: "i-lucide-binary", blurb: "XOR, multiply, repeat. 64 bits of it" },
  scrypt: { icon: "i-lucide-hourglass", blurb: "Slow on purpose and hungry for memory" },
  pbkdf2: { icon: "i-lucide-key-round", blurb: "HMAC a few hundred thousand times" },
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

/**
 * The label a page shows for a family.
 *
 * @param {HashFamily} family - A family as `info().family` reports it.
 * @returns {string} Its label.
 */
export function familyLabel(family: HashFamily): string {
  return FAMILY_LABELS[family];
}

/**
 * How many built-ins the library files under one family.
 *
 * @param {HashFamily} family - A family as `info().family` reports it.
 * @returns {number} The count in the registry.
 */
export function familySize(family: HashFamily): number {
  return ALGORITHMS.filter((algorithm) => algorithm.info.family === family).length;
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
 * The options an algorithm takes besides the output encoding and the HMAC key, which every
 * digest shares.
 *
 * @param {AlgorithmInfo} info - The algorithm's metadata.
 * @returns {AlgorithmInfo["options"]} Salt, seed and cost parameters, in declared order.
 */
export function ownOptions(info: AlgorithmInfo): AlgorithmInfo["options"] {
  return info.options.filter((option) => option.name !== "encoding" && option.name !== "key");
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

/**
 * Options an algorithm page hashes its sample with. The KDFs get a fixed salt and a small cost,
 * so the page stays reproducible and doesn't spend seconds on 600000 PBKDF2 rounds.
 */
export const SAMPLE_OPTIONS: Partial<Record<BuiltinAlgorithm, Record<string, string | number>>> = {
  scrypt: { salt: "73616c74", N: 1024 },
  pbkdf2: { salt: "73616c74", iterations: 1000 },
};
