/** Checksum manifests in the tag format `sha256sum --tag` writes and `sha256sum -c` reads. */
import { HashError, InvalidOptionError } from "./errors.ts";
import type { Hash } from "./hash.ts";
import { Kdf } from "./kdf.ts";
import { resolveAlgorithm } from "./resolve.ts";

/** One file of a manifest. */
export interface ManifestEntry {
  /** Registry name of the algorithm. */
  algorithm: string;
  /** Path relative to the manifest's root, with `/` between directories. */
  path: string;
  /** Lowercase hex digest. */
  digest: string;
}

/** An entry read from a manifest, with the line it came from. */
export interface ParsedManifestEntry extends ManifestEntry {
  /** Line number, from 1. */
  line: number;
}

/** Tags GNU coreutils writes, so `sha256sum -c` and `cksum -c` read the manifest too. */
const COREUTILS_TAGS: Readonly<Record<string, string>> = {
  md5: "MD5",
  sha1: "SHA1",
  sha224: "SHA224",
  sha256: "SHA256",
  sha384: "SHA384",
  sha512: "SHA512",
  "sha3-256": "SHA3-256",
  "sha3-512": "SHA3-512",
  blake2b: "BLAKE2b",
  "blake2b-256": "BLAKE2b-256",
};

const TAG_LINE = /^(?<tag>[^\s()]+) \((?<path>.*)\) = (?<digest>[0-9A-Fa-f]+)$/su;
const GNU_LINE = /^(?<digest>[0-9A-Fa-f]+) [ *](?<path>.+)$/su;
const ESCAPED = /[\\\n\r]/u;

/**
 * Resolves an algorithm a manifest can name; a KDF's salt has no room in the format.
 *
 * @param name - Algorithm name or label, such as `SHA256` from a tag.
 * @returns {Hash} The algorithm, with its default options.
 */
export function manifestAlgorithm(name: string): Hash {
  const hash = resolveAlgorithm(name);
  if (hash instanceof Kdf) {
    throw new InvalidOptionError(
      "algorithm",
      hash.name(),
      "derives keys from a salt and a cost, which a checksum manifest has no place for",
    );
  }
  return hash;
}

/**
 * Writes one manifest line, without the line feed.
 *
 * @param entry - The file and its digest.
 * @returns {string} The line.
 */
export function manifestLine(entry: Readonly<ManifestEntry>): string {
  const tag = Object.hasOwn(COREUTILS_TAGS, entry.algorithm)
    ? COREUTILS_TAGS[entry.algorithm]!
    : entry.algorithm;
  const line = `${tag} (${escapePath(entry.path)}) = ${entry.digest}`;
  return ESCAPED.test(entry.path) ? `\\${line}` : line;
}

/**
 * Writes one line the way plain `sha256sum` does: digest, two spaces, path.
 *
 * @param entry - The file and its digest.
 * @returns {string} The line.
 */
export function plainLine(entry: Readonly<Pick<ManifestEntry, "path" | "digest">>): string {
  const line = `${entry.digest}  ${escapePath(entry.path)}`;
  return ESCAPED.test(entry.path) ? `\\${line}` : line;
}

/**
 * Reads tag lines, or plain `sha256sum` lines when `algorithm` names them.
 *
 * @param text - The manifest.
 * @param algorithm - The algorithm of untagged lines.
 * @returns {ParsedManifestEntry[]} The entries, in the order given.
 */
export function parseManifest(text: string, algorithm?: string): ParsedManifestEntry[] {
  const untagged = algorithm === undefined ? undefined : manifestAlgorithm(algorithm);
  const lengths: Record<string, number> = {};
  const entries = text.split(/\r?\n/u).flatMap((raw, index) => {
    if (raw === "") return [];
    const entry = parseLine(raw, { line: index + 1, untagged });
    lengths[entry.algorithm] = assertDigestLength(entry, lengths);
    return [entry];
  });
  if (entries.length === 0) {
    throw new HashError("The manifest lists no files, and an empty manifest proves nothing");
  }
  return entries;
}

/**
 * Reads one line in either format.
 *
 * @param raw - The line as written.
 * @param context - Its number, and the algorithm of a `sha256sum` line, if known.
 * @returns {ParsedManifestEntry} The entry.
 */
function parseLine(
  raw: string,
  context: Readonly<{ line: number; untagged: Hash | undefined }>,
): ParsedManifestEntry {
  const { line, untagged } = context;
  const escaped = raw.startsWith("\\");
  const body = escaped ? raw.slice(1) : raw;
  const tagged = TAG_LINE.exec(body)?.groups;
  if (tagged !== undefined) {
    const hash = settledAlgorithm(tagged["tag"]!, line);
    return entryOf(hash.name(), { ...tagged, line, escaped });
  }
  const gnu = GNU_LINE.exec(body)?.groups;
  if (gnu === undefined)
    throw lineError(line, "is neither `ALG (path) = digest` nor `digest  path`");
  if (untagged === undefined) {
    throw lineError(line, "names no algorithm; pass the one that made the manifest");
  }
  return entryOf(untagged.name(), { ...gnu, line, escaped });
}

/**
 * Builds an entry from the matched parts of a line.
 *
 * @param algorithm - The algorithm's key.
 * @param parts - The path and digest as written, the line number and whether the path is escaped.
 * @returns {ParsedManifestEntry} The entry.
 */
function entryOf(
  algorithm: string,
  parts: Readonly<{ path?: string; digest?: string; line: number; escaped: boolean }>,
): ParsedManifestEntry {
  const written = parts.path ?? "";
  const path = (parts.escaped ? unescapePath(written, parts.line) : written)
    .split("/")
    .filter((part) => part !== ".")
    .join("/");
  assertRelative(path, parts.line);
  return { algorithm, path, digest: (parts.digest ?? "").toLowerCase(), line: parts.line };
}

/**
 * Resolves a line's tag, naming the line when it fails.
 *
 * @param tag - The tag as written.
 * @param line - The line number.
 * @returns {Hash} The algorithm.
 */
function settledAlgorithm(tag: string, line: number): Hash {
  try {
    return manifestAlgorithm(tag);
  } catch (error) {
    throw lineError(
      line,
      `names ${tag}: ${error instanceof Error ? error.message : String(error)}`,
    );
  }
}

/**
 * Refuses a digest no file could match, by its length.
 *
 * @param entry - The entry.
 * @param lengths - Hex digits per algorithm seen so far.
 * @returns {number} The algorithm's hex digits.
 */
function assertDigestLength(
  entry: Readonly<ParsedManifestEntry>,
  lengths: Readonly<Record<string, number>>,
): number {
  const length = Object.hasOwn(lengths, entry.algorithm)
    ? lengths[entry.algorithm]!
    : manifestAlgorithm(entry.algorithm).hash(new Uint8Array()).digestLength * 2;
  if (entry.digest.length !== length) {
    throw lineError(
      entry.line,
      `has ${entry.digest.length} hex digits, and ${entry.algorithm} gives ${length}`,
    );
  }
  return length;
}

/**
 * Refuses a path that leaves the root or names nothing.
 *
 * @param path - The path from the line.
 * @param line - The line number.
 */
function assertRelative(path: string, line: number): void {
  const parts = path.split("/");
  if (path === "" || path.startsWith("/") || path.includes("\0")) {
    throw lineError(line, "needs a path relative to the root");
  }
  if (parts.some((part) => part === ".." || part === "") || path.endsWith("/")) {
    throw lineError(line, "has an empty or `..` part in its path");
  }
}

/**
 * Escapes a path the way GNU coreutils does.
 *
 * @param path - The path.
 * @returns {string} The path with `\\`, `\n` and `\r` in place of those characters.
 */
function escapePath(path: string): string {
  return path.replaceAll("\\", "\\\\").replaceAll("\n", "\\n").replaceAll("\r", "\\r");
}

/**
 * Undoes `escapePath`, refusing escapes GNU never writes.
 *
 * @param path - The escaped path.
 * @param line - The line number.
 * @returns {string} The path.
 */
function unescapePath(path: string, line: number): string {
  return path.replaceAll(/\\(?<code>.?)/gsu, (_match, code: string) => {
    if (code === "\\") return "\\";
    if (code === "n") return "\n";
    if (code === "r") return "\r";
    throw lineError(line, `has an unknown escape \\${code} in its path`);
  });
}

/**
 * The error for a line that can't be read.
 *
 * @param line - The line number.
 * @param reason - What is wrong with it.
 * @returns {HashError} The error.
 */
function lineError(line: number, reason: string): HashError {
  return new HashError(`Manifest line ${line} ${reason}`);
}
