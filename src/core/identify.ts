/**
 * Hash identification. A digest carries no name, so all there is to go on is its shape: a prefix
 * such as `$2b$`, or how many bytes its hex or base64 spells. The answer narrows the guess; only
 * hashing a known input and getting a match settles it.
 */
import { kdfDigests } from "../algorithms/pbkdf2.ts";
import { bcryptBase64, BCRYPT_MAX_COST, BCRYPT_MIN_COST } from "./bcrypt.ts";
import { parameterText } from "./digest.ts";
import { InvalidOptionError } from "./errors.ts";
import { algorithms, create, has } from "./registry.ts";

/** What fits: a format's whole layout, its prefix alone, the digest size, or a KDF's output. */
export type DigestFit = "format" | "prefix" | "length" | "keyLength";

/** One algorithm or format a hash may come from. */
export interface DigestCandidate {
  /** Registry name, or the usual name of a format or algorithm this package lacks. */
  name: string;
  /** Human-readable label. */
  label: string;
  /** What fits. */
  fit: DigestFit;
  /** The registered algorithm that computes it, absent when this package cannot. */
  algorithm?: string;
  /** The salt in hex, read out of the string. */
  salt?: string;
  /** Options to pass with `algorithm`, read out of the string. */
  parameters?: Record<string, number | string>;
  /** The digest in hex, read out of the string, to verify against. */
  expected?: string;
  /** What else the shape tells. */
  note?: string;
}

/** What `identifyDigest` found. */
export interface DigestIdentity {
  /** How the string was read: by its prefix, as hex, as base64, or not at all. */
  reading: "format" | "hex" | "base64" | "unknown";
  /** Bytes the hex or base64 spells. */
  length?: number;
  /** Those bytes in hex. */
  hex?: string;
  /** Why nothing fits, when nothing does. */
  note?: string;
  /** Most likely first. */
  candidates: DigestCandidate[];
}

/** What a format reader takes out of a string whose layout fits. */
type FormatReading = Pick<
  DigestCandidate,
  "algorithm" | "salt" | "parameters" | "expected" | "note"
>;

/** The groups a format's layout captured. */
type Match = readonly (string | undefined)[];

/** A string format a hash comes wrapped in, recognized by its prefix. */
interface DigestFormat {
  name: string;
  label: string;
  prefixes: readonly string[];
  /** The whole layout. */
  layout: RegExp;
  /** Reads the parts out of a string the layout matched. */
  read?: (match: Match) => FormatReading;
}

/**
 * Decodes base64, either alphabet, with or without padding. Passlib writes `.` for `+`.
 *
 * @param text - The base64 text.
 * @returns {Uint8Array} The bytes.
 */
function base64(text: string): Uint8Array {
  const standard = text.replaceAll(".", "+").replaceAll("-", "+").replaceAll("_", "/");
  return Uint8Array.fromBase64(standard);
}

/**
 * Reads an Argon2 PHC string. This package runs Argon2 version 19 (0x13) only.
 *
 * @param match - Variant, version, memory, iterations, parallelism, salt and hash.
 * @returns {FormatReading} The call that recomputes it.
 */
function readArgon2(match: Match): FormatReading {
  const [, variant, version = "16", memory, iterations, parallelism, salt, hash] = match;
  if (version !== "19") {
    return { note: `version ${version}, while this package runs 19` };
  }
  const expected = base64(hash!);
  return {
    algorithm: variant!,
    salt: base64(salt!).toHex(),
    parameters: {
      memory: Number(memory),
      iterations: Number(iterations),
      parallelism: Number(parallelism),
      keyLength: expected.length,
    },
    expected: expected.toHex(),
  };
}

/**
 * Builds the reading of a PBKDF2 string, refusing a digest PBKDF2 here does not run over.
 *
 * @param digest - The hash PBKDF2 ran HMAC over.
 * @param iterations - Its iteration count.
 * @param salt - The salt's bytes.
 * @param hash - The derived key.
 * @returns {FormatReading} The call that recomputes it.
 */
function pbkdf2Reading(
  digest: string,
  iterations: string,
  salt: Uint8Array,
  hash: Uint8Array,
): FormatReading {
  const digests = kdfDigests();
  if (!digests.split(", ").includes(digest)) {
    return { note: `over ${digest}, while pbkdf2 here takes ${digests}` };
  }
  return {
    algorithm: "pbkdf2",
    salt: salt.toHex(),
    parameters: { iterations: Number(iterations), digest, keyLength: hash.length },
    expected: hash.toHex(),
  };
}

/**
 * Reads a passlib PBKDF2 string, whose prefix names the digest: `$pbkdf2$` alone means SHA-1.
 *
 * @param digest - The hash the prefix names.
 * @param match - Iterations, salt and hash.
 * @returns {FormatReading} The call that recomputes it.
 */
function readPasslibPbkdf2(digest: string, match: Match): FormatReading {
  const [, iterations, salt, hash] = match;
  return pbkdf2Reading(digest, iterations!, base64(salt!), base64(hash!));
}

/**
 * Reads a Django PBKDF2 string, whose salt is plain text.
 *
 * @param match - Digest, iterations, salt and hash.
 * @returns {FormatReading} The call that recomputes it.
 */
function readDjangoPbkdf2(match: Match): FormatReading {
  const [, digest, iterations, salt, hash] = match;
  return pbkdf2Reading(digest!, iterations!, new TextEncoder().encode(salt), base64(hash!));
}

/**
 * Reads a passlib scrypt string, where `ln` is the base-2 logarithm of N.
 *
 * @param match - ln, r, p, salt and hash.
 * @returns {FormatReading} The call that recomputes it.
 */
function readPasslibScrypt(match: Match): FormatReading {
  const [, ln, r, p, salt, hash] = match;
  const expected = base64(hash!);
  return {
    algorithm: "scrypt",
    salt: base64(salt!).toHex(),
    parameters: { N: 2 ** Number(ln), r: Number(r), p: Number(p), keyLength: expected.length },
    expected: expected.toHex(),
  };
}

/** Why a `$2a$` MISMATCH may still be the right password (CVE-2011-2483). */
const OLD_2A = "crypt_blowfish before 1.1 wrote $2a$ with the sign bug for non-ASCII passwords";

/**
 * Reads a bcrypt string. `$2a$` and `$2y$` hash as `$2b$` does for the 72 bytes bcrypt reads.
 *
 * @param match - Variant, cost, salt and hash.
 * @returns {FormatReading} The call that recomputes it.
 */
function readBcrypt(match: Match): FormatReading {
  const [, variant, digits, salt, hash] = match;
  const cost = Number(digits);
  if (variant === "x") {
    return { note: `cost ${cost}, $2x$ is crypt_blowfish's sign bug` };
  }
  if (cost < BCRYPT_MIN_COST || cost > BCRYPT_MAX_COST) {
    return { note: `cost ${cost}, while bcrypt takes ${BCRYPT_MIN_COST} to ${BCRYPT_MAX_COST}` };
  }
  return {
    ...(variant === "a" ? { note: OLD_2A } : {}),
    algorithm: "bcrypt",
    salt: bcryptBase64(salt!).toHex(),
    parameters: { cost },
    expected: bcryptBase64(hash!).toHex(),
  };
}

const CRYPT = "[./A-Za-z0-9]";

/**
 * The formats a hash comes in, behind a call since esbuild keeps a module-level `new RegExp`.
 *
 * @returns {DigestFormat[]} The formats, the more specific prefix first.
 */
function digestFormats(): DigestFormat[] {
  const argon2 = (variant: string, label: string): DigestFormat => ({
    name: variant,
    label: `${label}, PHC string`,
    prefixes: [`$${variant}$`, `argon2$${variant}$`],
    layout: new RegExp(
      String.raw`^(?:argon2)?\$(argon2(?:id|i|d))\$(?:v=(\d{1,10})\$)?m=(\d{1,10}),t=(\d{1,10}),p=(\d{1,10})\$([A-Za-z0-9+/]+)\$([A-Za-z0-9+/]+)$`,
    ),
    read: readArgon2,
  });
  return [
    argon2("argon2id", "Argon2id"),
    argon2("argon2i", "Argon2i"),
    argon2("argon2d", "Argon2d"),
    {
      name: "bcrypt",
      label: "bcrypt",
      prefixes: ["$2a$", "$2b$", "$2x$", "$2y$"],
      layout: new RegExp(String.raw`^\$2([abxy])\$(\d{2})\$(${CRYPT}{22})(${CRYPT}{31})$`),
      read: readBcrypt,
    },
    {
      name: "scrypt",
      label: "scrypt, passlib",
      prefixes: ["$scrypt$"],
      layout: new RegExp(
        String.raw`^\$scrypt\$ln=(\d{1,2}),r=(\d{1,10}),p=(\d{1,10})\$(${CRYPT}*)\$(${CRYPT}+)$`,
      ),
      read: readPasslibScrypt,
    },
    {
      name: "scrypt-crypt",
      label: "scrypt, crypt(3)",
      prefixes: ["$7$"],
      layout: new RegExp(String.raw`^\$7\$${CRYPT}{11,}\$${CRYPT}{43}$`),
      read: () => ({
        note: "scrypt underneath, its costs and salt in an encoding this package does not read",
      }),
    },
    {
      name: "yescrypt",
      label: "yescrypt",
      prefixes: ["$y$"],
      layout: new RegExp(String.raw`^\$y\$${CRYPT}+\$${CRYPT}*\$${CRYPT}{43}$`),
    },
    {
      name: "sha512crypt",
      label: "SHA-512 crypt",
      prefixes: ["$6$"],
      layout: new RegExp(String.raw`^\$6\$(?:rounds=\d+\$)?[^$:\s]{0,16}\$${CRYPT}{86}$`),
    },
    {
      name: "sha256crypt",
      label: "SHA-256 crypt",
      prefixes: ["$5$"],
      layout: new RegExp(String.raw`^\$5\$(?:rounds=\d+\$)?[^$:\s]{0,16}\$${CRYPT}{43}$`),
    },
    {
      name: "md5crypt",
      label: "MD5 crypt",
      prefixes: ["$1$"],
      layout: new RegExp(String.raw`^\$1\$[^$:\s]{0,8}\$${CRYPT}{22}$`),
    },
    {
      name: "apr1",
      label: "Apache MD5 crypt",
      prefixes: ["$apr1$"],
      layout: new RegExp(String.raw`^\$apr1\$[^$:\s]{0,8}\$${CRYPT}{22}$`),
    },
    {
      name: "pbkdf2-sha256",
      label: "PBKDF2-SHA256, passlib",
      prefixes: ["$pbkdf2-sha256$"],
      layout: new RegExp(String.raw`^\$pbkdf2-sha256\$(\d{1,10})\$(${CRYPT}*)\$(${CRYPT}+)$`),
      read: (match) => readPasslibPbkdf2("sha256", match),
    },
    {
      name: "pbkdf2-sha512",
      label: "PBKDF2-SHA512, passlib",
      prefixes: ["$pbkdf2-sha512$"],
      layout: new RegExp(String.raw`^\$pbkdf2-sha512\$(\d{1,10})\$(${CRYPT}*)\$(${CRYPT}+)$`),
      read: (match) => readPasslibPbkdf2("sha512", match),
    },
    {
      name: "pbkdf2-sha1",
      label: "PBKDF2-SHA1, passlib",
      prefixes: ["$pbkdf2$"],
      layout: new RegExp(String.raw`^\$pbkdf2\$(\d{1,10})\$(${CRYPT}*)\$(${CRYPT}+)$`),
      read: (match) => readPasslibPbkdf2("sha1", match),
    },
    {
      name: "django-pbkdf2",
      label: "PBKDF2, Django",
      prefixes: ["pbkdf2_sha256$", "pbkdf2_sha1$"],
      layout: /^pbkdf2_(sha256|sha1)\$(\d{1,10})\$([^$]+)\$([A-Za-z0-9+/]+={0,2})$/,
      read: readDjangoPbkdf2,
    },
    {
      name: "mysql41",
      label: "MySQL 4.1 PASSWORD()",
      prefixes: ["*"],
      layout: /^\*([0-9A-Fa-f]{40})$/,
      read: (match) => ({
        algorithm: "sha1",
        parameters: { rounds: 2 },
        expected: match[1]!.toLowerCase(),
        note: "SHA-1 of the SHA-1 bytes",
      }),
    },
  ];
}

/** Common digests this package lacks, by byte length, so a guess can name them too. */
const OTHER_DIGESTS: readonly (readonly [number, string, string])[] = [
  [4, "crc32c", "CRC-32C"],
  [8, "mysql323", "MySQL 3.23 PASSWORD()"],
  [16, "md2", "MD2"],
  [16, "lm", "LM"],
  [24, "tiger192", "Tiger-192"],
  [28, "sha3-224", "SHA3-224"],
  [32, "streebog256", "Streebog-256"],
  [32, "gost94", "GOST R 34.11-94"],
  [48, "sha3-384", "SHA3-384"],
  [64, "whirlpool", "Whirlpool"],
  [64, "streebog512", "Streebog-512"],
];

/** The digests met most often, first among those of their length; the rest keep registry order. */
const COMMON_DIGESTS: readonly string[] = ["md5", "sha1", "sha256", "sha512", "sha384", "sha224"];

/** Shortest output a KDF is listed for: a shorter one is a checksum far more often. */
const MIN_KDF_LENGTH = 16;

/**
 * Lists what a string of `$`-separated parts may be, by its prefix.
 *
 * @param text - The trimmed string.
 * @returns {DigestCandidate[]} The formats whose prefix it has.
 */
function formatCandidates(text: string): DigestCandidate[] {
  const found: DigestCandidate[] = [];
  for (const format of digestFormats()) {
    if (!format.prefixes.some((prefix) => text.startsWith(prefix))) continue;
    const candidate: DigestCandidate = { name: format.name, label: format.label, fit: "prefix" };
    const match = format.layout.exec(text);
    const reading = match ? readFormat(format.read, match) : undefined;
    found.push(reading ? { ...candidate, fit: "format", ...reading } : candidate);
  }
  return found;
}

/**
 * Reads a matched string, or nothing when a part fails to decode, such as base64 one digit short.
 *
 * @param read - The reader of the format whose layout matched.
 * @param match - What it captured.
 * @returns {FormatReading | undefined} What the string holds.
 */
function readFormat(read: DigestFormat["read"], match: Match): FormatReading | undefined {
  if (!read) return {};
  try {
    return read(match);
  } catch {
    return undefined;
  }
}

/**
 * Lists the algorithms whose digest, or KDF output, is `length` bytes.
 *
 * @param length - Bytes the string spells.
 * @param prefixed - Whether it was hex after `0x`.
 * @returns {DigestCandidate[]} Fixed digests first, then digests this package lacks, then KDFs.
 */
function lengthCandidates(length: number, prefixed: boolean): DigestCandidate[] {
  const fixed: DigestCandidate[] = [];
  const kdfs: DigestCandidate[] = [];
  for (const name of algorithms()) {
    const info = create(name).info();
    if (info.digestLength === length) {
      fixed.push({ name, label: info.label, fit: "length", algorithm: name });
    } else if (
      info.digestLength === undefined &&
      length >= MIN_KDF_LENGTH &&
      info.options.some((option) => option.name === "keyLength")
    ) {
      kdfs.push({
        name,
        label: info.label,
        fit: "keyLength",
        algorithm: name,
        parameters: { keyLength: length },
      });
    }
  }
  const rank = (name: string): number => {
    const index = COMMON_DIGESTS.indexOf(name);
    return index === -1 ? COMMON_DIGESTS.length : index;
  };
  fixed.sort((a, b) => rank(a.name) - rank(b.name));
  const keccak = fixed.findIndex((candidate) => candidate.name === "keccak256");
  if (prefixed && keccak > 0) {
    const [moved] = fixed.splice(keccak, 1);
    fixed.unshift({ ...moved!, note: "0x is how Ethereum writes Keccak-256" });
  }
  const other: DigestCandidate[] = OTHER_DIGESTS.filter(
    ([size, name]) => size === length && !has(name),
  ).map(([, name, label]) => ({ name, label, fit: "length" }));
  return [...fixed, ...other, ...kdfs];
}

/**
 * Reads base64, either alphabet, padded or not.
 *
 * @param text - The trimmed string.
 * @returns {Uint8Array | undefined} The bytes, or nothing when it is not base64.
 */
function base64Bytes(text: string): Uint8Array | undefined {
  if (!/^(?:[A-Za-z0-9+/]+|[A-Za-z0-9_-]+)={0,2}$/.test(text)) return undefined;
  try {
    return base64(text);
  } catch {
    return undefined;
  }
}

/**
 * Lists the algorithms a hash may come from by its prefix or byte length, most likely first.
 * A format this package computes comes with the salt, costs and digest read out of the string.
 *
 * @param text - The hash as found.
 * @returns {DigestIdentity} How it was read and the candidates.
 */
export function identifyDigest(text: string): DigestIdentity {
  if (typeof text !== "string") {
    throw new InvalidOptionError("digest", typeof text, "must be a string");
  }
  const trimmed = text.trim();
  if (trimmed === "") throw new InvalidOptionError("digest", "(empty)", "must not be empty");
  const formats = formatCandidates(trimmed);
  if (formats.length > 0) return { reading: "format", candidates: formats };
  if (trimmed.startsWith("$")) {
    return {
      reading: "unknown",
      note: "a $ prefix no known format uses",
      candidates: [],
    };
  }
  const hex = /^(0x)?([0-9A-Fa-f]+)$/.exec(trimmed);
  if (hex) {
    if (hex[2]!.length % 2 === 1) {
      return { reading: "unknown", note: "an odd number of hex digits", candidates: [] };
    }
    const bytes = Uint8Array.fromHex(hex[2]!);
    return identity("hex", bytes, lengthCandidates(bytes.length, hex[1] !== undefined));
  }
  const bytes = base64Bytes(trimmed);
  if (bytes) return identity("base64", bytes, lengthCandidates(bytes.length, false));
  return { reading: "unknown", note: "neither hex, base64 nor a known format", candidates: [] };
}

/**
 * Builds the identity of a hex or base64 string.
 *
 * @param reading - How it was read.
 * @param bytes - What it spells.
 * @param candidates - What makes that many bytes.
 * @returns {DigestIdentity} The identity.
 */
function identity(
  reading: "hex" | "base64",
  bytes: Uint8Array,
  candidates: readonly DigestCandidate[],
): DigestIdentity {
  const found: DigestIdentity = {
    reading,
    length: bytes.length,
    hex: bytes.toHex(),
    candidates: [...candidates],
  };
  return candidates.length > 0
    ? found
    : { ...found, note: `nothing known here makes ${bytes.length} bytes` };
}

/**
 * Says how an identity was read, and whether candidates follow.
 *
 * @param found - The identity.
 * @returns {string} One line.
 */
function identityHeading(found: DigestIdentity): string {
  const note = found.note ?? "no candidate";
  if (found.reading === "unknown") return `Not identified: ${note}.`;
  const read =
    found.reading === "format" ? "Read by its prefix" : `${found.length} bytes in ${found.reading}`;
  return found.candidates.length > 0
    ? `${read}. Candidates from the shape alone, most likely first:`
    : `${read}: ${note}.`;
}

/**
 * Lines for the CLI and the tools: a heading, one per candidate, the KDFs together last.
 *
 * @param found - The identity.
 * @returns {{ heading: string; lines: string[] }} The heading and the candidate lines.
 */
export function identityText(found: DigestIdentity): {
  heading: string;
  lines: string[];
} {
  const lines = found.candidates
    .filter((candidate) => candidate.fit !== "keyLength")
    .map((candidate) => candidateLine(candidate));
  if (found.reading === "base64" && found.hex !== undefined) lines.unshift(`hex ${found.hex}`);
  const kdfs = found.candidates.filter((candidate) => candidate.fit === "keyLength");
  if (kdfs.length > 0) {
    lines.push(
      `Any length: ${kdfs.map((candidate) => candidate.name).join(", ")}, with keyLength ${found.length}`,
    );
  }
  return { heading: identityHeading(found), lines };
}

/**
 * Describes one candidate: its name, whether this package computes it, and with what.
 *
 * @param candidate - The candidate.
 * @returns {string} One line.
 */
function candidateLine(candidate: DigestCandidate): string {
  const { algorithm, expected, note, parameters, salt } = candidate;
  const parts = [`${candidate.name}: ${candidate.label}`];
  if (candidate.fit === "prefix") return `${parts[0]}, the prefix fits, the rest does not`;
  if (note !== undefined) parts.push(note);
  if (algorithm === undefined) {
    parts.push("not in this package");
  } else {
    parts.push(algorithm === candidate.name ? "computable" : `computable as ${algorithm}`);
    const given = parameterText({ ...(salt === undefined ? {} : { salt }), ...parameters });
    if (given !== "") parts.push(given);
    if (expected !== undefined) parts.push(`expected ${expected}`);
  }
  return parts.join(", ");
}
