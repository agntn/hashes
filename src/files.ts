/** Files on disk and their manifests. It imports `node:fs`, so the root never loads it. */
import { createReadStream, type Dirent } from "node:fs";
import { lstat, readFile, readdir, realpath, stat } from "node:fs/promises";
import { isAbsolute, join, matchesGlob, relative, resolve, sep } from "node:path";
import { BlockHash } from "./core/block-hash.ts";
import { encodeDigest } from "./core/digest.ts";
import { HashError, InvalidOptionError, quoted } from "./core/errors.ts";
import type { Hash } from "./core/hash.ts";
import {
  manifestAlgorithm,
  manifestLine,
  parseManifest,
  type ManifestEntry,
  type ParsedManifestEntry,
} from "./core/manifest.ts";
import { resolveAlgorithm } from "./core/resolve.ts";
import type { HashOptions, HashResult } from "./core/types.ts";

export {
  manifestLine,
  parseManifest,
  type ManifestEntry,
  type ParsedManifestEntry,
} from "./core/manifest.ts";

/** Options for one file's digest: the algorithm and whatever it takes. */
export interface FileHashOptions extends HashOptions {
  /** Algorithm name or label. */
  algorithm: string;
}

/** Which files of a directory a manifest covers. */
export interface ManifestSelection {
  /** Directory the paths are relative to. Default: the current directory. */
  root?: string;
  /** Globs of relative paths to leave out, such as `node_modules/**`. */
  exclude?: readonly string[];
}

/** Options for writing a manifest. */
export interface CreateManifestOptions extends ManifestSelection {
  /** Algorithm name or label. */
  algorithm: string;
  /** The manifest's own file, left out of the listing. */
  output?: string;
}

/** What a manifest covers and the lines that say so. */
export interface CreatedManifest {
  /** Every file, sorted by path. */
  entries: ManifestEntry[];
  /** Symlinks and other entries that are not regular files, left out. */
  skipped: string[];
  /** The manifest, a line per file, ending with a line feed. */
  text: string;
}

/** Options for checking a manifest. */
export interface CheckManifestOptions extends ManifestSelection {
  /** Algorithm of untagged `sha256sum` lines. */
  algorithm?: string;
  /** Also report files under the root the manifest doesn't list. */
  strict?: boolean;
  /** The manifest's own file, never an extra one. */
  manifest?: string;
}

/** How one file compares with its line. */
export type ManifestStatus = "ok" | "mismatch" | "missing" | "unreadable" | "extra";

/** The verdict on one file. */
export interface ManifestResult {
  path: string;
  status: ManifestStatus;
  /** Algorithm of the line, absent for an extra file. */
  algorithm?: string;
  /** Digest the line expects. */
  expected?: string;
  /** Digest of the file as it is now. */
  actual?: string;
  /** Why a file could not be read. */
  reason?: string;
}

/** The verdict on a whole manifest. */
export interface ManifestCheck {
  /** One result per line, then one per extra file. */
  results: ManifestResult[];
  /** Whether every file matched and, when strict, none was extra. */
  ok: boolean;
}

/**
 * Hashes a file's bytes exactly as they are on disk.
 *
 * @param path - The file.
 * @param options - The algorithm, then its options as `hash()` takes them.
 * @returns {Promise<HashResult>} The digest, the same one `hash()` gives for the file's bytes.
 */
export async function hashFile(
  path: string,
  options: Readonly<FileHashOptions>,
): Promise<HashResult> {
  const { algorithm, ...rest } = options;
  const hash = resolveAlgorithm(algorithm);
  try {
    if (!streams(hash, rest)) return hash.hash(new Uint8Array(await readFile(path)), rest);
    const shape = hash.hash(new Uint8Array(), rest);
    const hasher = hash.hasher(rest);
    for await (const chunk of createReadStream(path)) hasher.update(chunk as Uint8Array);
    const { encoding: _encoding, ...reported } = shape.options;
    return encodeDigest(hasher.digest(), shape.algorithm, "hash", shape.encoding, reported);
  } catch (error) {
    throw readError(path, error);
  }
}

/**
 * Tells whether the hasher can take the file in chunks: one plain round, no key.
 *
 * @param hash - The algorithm.
 * @param options - The caller's options.
 * @returns {hash is BlockHash} Whether it streams.
 */
function streams(hash: Hash, options: Readonly<HashOptions>): hash is BlockHash {
  const plain = Object.keys(options).every((name) => name === "encoding");
  return hash instanceof BlockHash && plain;
}

/**
 * Writes a manifest of every regular file under the root; an empty one proves nothing.
 *
 * @param options - The algorithm, the root, the exclusions and where the manifest goes.
 * @returns {Promise<CreatedManifest>} The entries, what was skipped and the manifest text.
 */
export async function createManifest(
  options: Readonly<CreateManifestOptions>,
): Promise<CreatedManifest> {
  const hash = manifestAlgorithm(options.algorithm);
  const root = resolve(options.root ?? ".");
  const { files, skipped } = await inventory(root, {
    exclude: options.exclude ?? [],
    own: await identity(options.output),
  });
  if (files.length === 0) {
    throw new InvalidOptionError(
      "root",
      root,
      "holds no files to list, and an empty manifest proves nothing",
    );
  }
  const entries: ManifestEntry[] = [];
  for (const path of files) {
    const { digest } = await hashFile(join(root, path), { algorithm: hash.name() });
    entries.push({ algorithm: hash.name(), path, digest: String(digest) });
  }
  const text = entries.map((entry) => `${manifestLine(entry)}\n`).join("");
  return { entries, skipped, text };
}

/**
 * Checks every listed file; strict also fails on files the manifest leaves out.
 *
 * @param text - The manifest.
 * @param options - The root, the algorithm of untagged lines, and the strict inventory.
 * @returns {Promise<ManifestCheck>} A result per file.
 */
export async function checkManifest(
  text: string,
  options: Readonly<CheckManifestOptions> = {},
): Promise<ManifestCheck> {
  const entries = parseManifest(text, options.algorithm);
  const root = resolve(options.root ?? ".");
  const realRoot = await realpath(root).catch((error: unknown) => {
    throw readError(root, error);
  });
  const results: ManifestResult[] = [];
  for (const entry of entries) results.push(await checkEntry(entry, { root, realRoot }));
  if (options.strict === true) {
    const listed = new Set(entries.map((entry) => join(root, entry.path)));
    const { files } = await inventory(root, {
      exclude: options.exclude ?? [],
      own: await identity(options.manifest),
    });
    for (const path of files) {
      if (!listed.has(join(root, path))) results.push({ path, status: "extra" });
    }
  }
  return { results, ok: results.every((result) => result.status === "ok") };
}

/**
 * Checks one line against the file it names, never through a symlink.
 *
 * @param entry - The line.
 * @param where - The root as given and as it resolves.
 * @returns {Promise<ManifestResult>} The verdict.
 */
async function checkEntry(
  entry: Readonly<ParsedManifestEntry>,
  where: Readonly<{ root: string; realRoot: string }>,
): Promise<ManifestResult> {
  const line = { path: entry.path, algorithm: entry.algorithm, expected: entry.digest };
  const path = join(where.root, entry.path);
  if (outside(where.root, path)) {
    return { ...line, status: "unreadable", reason: "leaves the root on this system" };
  }
  const problem = await unreadable(path, join(where.realRoot, entry.path));
  if (problem === "missing") return { ...line, status: "missing" };
  if (problem !== undefined) return { ...line, status: "unreadable", reason: problem };
  try {
    const actual = String((await hashFile(path, { algorithm: entry.algorithm })).digest);
    return { ...line, status: actual === entry.digest ? "ok" : "mismatch", actual };
  } catch (error) {
    if (error instanceof FileReadError)
      return { ...line, status: "unreadable", reason: error.code };
    if (error instanceof HashError) return { ...line, status: "unreadable", reason: error.message };
    throw error;
  }
}

/**
 * Tells whether a joined path ended up outside the root, as `..\\x` does on Windows.
 *
 * @param root - The root.
 * @param path - The root joined with a manifest path.
 * @returns {boolean} Whether it escaped.
 */
function outside(root: string, path: string): boolean {
  const way = relative(root, path);
  return way === ".." || way.startsWith(`..${sep}`) || isAbsolute(way);
}

/**
 * Tells why a listed path can't be checked.
 *
 * @param path - The path under the root as given.
 * @param expected - Where it lands with no symlink on the way.
 * @returns {Promise<string | undefined>} `missing`, a reason, or nothing for a plain file.
 */
async function unreadable(path: string, expected: string): Promise<string | undefined> {
  try {
    const entry = await lstat(path);
    if (entry.isSymbolicLink()) return "is a symlink, which a check never follows";
    if (!entry.isFile()) return "is not a regular file";
    if ((await realpath(path)) !== expected) return "sits behind a symlinked directory";
    return undefined;
  } catch (error) {
    const code = codeOf(error);
    if (code === "ENOENT" || code === "ENOTDIR") return "missing";
    return code ?? String(error);
  }
}

/** A file as the filesystem knows it, whatever path or link leads there. */
interface Identity {
  dev: number;
  ino: number;
}

/**
 * Reads which file a path is, `/dev/stdout` included.
 *
 * @param path - The manifest's path, if any.
 * @returns {Promise<Identity | undefined>} Its device and inode, if it exists.
 */
async function identity(path: string | undefined): Promise<Identity | undefined> {
  if (path === undefined) return undefined;
  try {
    const { dev, ino } = await stat(path);
    return { dev, ino };
  } catch {
    return undefined;
  }
}

/**
 * Tells whether a file is the manifest itself.
 *
 * @param path - The file.
 * @param own - The manifest's identity.
 * @returns {Promise<boolean>} Whether they are one file.
 */
async function isOwn(path: string, own: Readonly<Identity> | undefined): Promise<boolean> {
  if (own === undefined) return false;
  const { dev, ino } = await lstat(path);
  return dev === own.dev && ino === own.ino;
}

/**
 * Lists the regular files under a directory, sorted by relative path.
 *
 * @param root - The directory.
 * @param rules - The exclusions and the manifest's own path.
 * @returns {Promise<{ files: string[]; skipped: string[] }>} The files, and what was not a file.
 */
async function inventory(
  root: string,
  rules: Readonly<{ exclude: readonly string[]; own: Readonly<Identity> | undefined }>,
): Promise<{ files: string[]; skipped: string[] }> {
  const files: string[] = [];
  const skipped: string[] = [];
  const pending = [""];
  for (let directory = pending.pop(); directory !== undefined; directory = pending.pop()) {
    for (const dirent of await listed(join(root, directory))) {
      const path =
        directory === ""
          ? nameOf(dirent.name, directory)
          : `${directory}/${nameOf(dirent.name, directory)}`;
      const isDirectory = dirent.isDirectory();
      if (excluded(isDirectory ? `${path}/` : path, rules.exclude)) continue;
      if (isDirectory) pending.push(path);
      else if (!dirent.isFile()) skipped.push(path);
      else if (!(await isOwn(join(root, path), rules.own))) files.push(path);
    }
  }
  return { files: files.toSorted(), skipped: skipped.toSorted() };
}

/**
 * Tells whether a path is excluded; a directory comes with a trailing `/`.
 *
 * @param path - The relative path.
 * @param patterns - The globs.
 * @returns {boolean} Whether to leave it out.
 */
function excluded(path: string, patterns: readonly string[]): boolean {
  return patterns.some(
    (pattern) => matchesGlob(path, pattern) || matchesGlob(path.replace(/\/$/u, ""), pattern),
  );
}

/**
 * Lists one directory with its names as bytes.
 *
 * @param directory - The directory.
 * @returns {Promise<Dirent<Buffer>[]>} Its entries.
 */
async function listed(directory: string): Promise<Dirent<Buffer>[]> {
  try {
    return await readdir(directory, { withFileTypes: true, encoding: "buffer" });
  } catch (error) {
    throw readError(directory, error);
  }
}

/**
 * Reads a file name as UTF-8, which a manifest line can name.
 *
 * @param name - The name's bytes.
 * @param directory - Its directory, for the error.
 * @returns {string} The name.
 */
function nameOf(name: Uint8Array, directory: string): string {
  try {
    return new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(name);
  } catch {
    const where = directory === "" ? "the root" : quoted(directory);
    throw new HashError(
      `A file name in ${where} is not UTF-8 (${name.toHex()}), so no manifest can name it`,
    );
  }
}

/**
 * Reads the code of a Node error.
 *
 * @param error - What was thrown.
 * @returns {string | undefined} `ENOENT`, `EACCES` and the like.
 */
function codeOf(error: unknown): string | undefined {
  return error instanceof Error && "code" in error ? String(error.code) : undefined;
}

/** A file the filesystem wouldn't read, with the code it gave, such as `EACCES`. */
class FileReadError extends HashError {
  readonly code: string;

  constructor(path: string, code: string) {
    super(`Can't read ${quoted(path)}: ${code}`);
    this.name = "FileReadError";
    this.code = code;
  }
}

/**
 * Turns a failed read into a `HashError` that names the file.
 *
 * @param path - The file.
 * @param error - What the read threw.
 * @returns {Error} The error to throw.
 */
function readError(path: string, error: unknown): Error {
  const code = codeOf(error);
  if (code === undefined) return error instanceof Error ? error : new HashError(String(error));
  return new FileReadError(path, code);
}
