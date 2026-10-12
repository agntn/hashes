import { HashError, InvalidOptionError, MissingOptionError } from "./errors.ts";
import type { Hash } from "./hash.ts";
import { Kdf } from "./kdf.ts";
import type { AlgorithmInfo, HashOptions, HashResult } from "./types.ts";

/**
 * Decodes an expected digest written in the result's encoding. Hex ignores case; base64 and
 * base64url are case-sensitive, so they are compared as bytes, never as lowercased text.
 *
 * @param expected - The digest to compare against, as text.
 * @param encoding - Its encoding.
 * @returns {Uint8Array | undefined} Its bytes, or undefined when it is not valid in that encoding.
 */
function decodeExpected(
  expected: string,
  encoding: HashResult["encoding"],
): Uint8Array | undefined {
  const trimmed = expected.trim();
  try {
    if (encoding === "hex") return Uint8Array.fromHex(trimmed);
    if (encoding === "base64") return Uint8Array.fromBase64(trimmed);
    if (encoding === "base64url") return Uint8Array.fromBase64(trimmed, { alphabet: "base64url" });
  } catch {
    return undefined;
  }
  throw new InvalidOptionError(
    "encoding",
    encoding,
    "compare a text digest: hex, base64 or base64url",
  );
}

/**
 * Refuses an expected digest that is not valid in its encoding. `digestMatches` answers false for
 * one, and a verify that printed that false would call a `0x`-prefixed hex digest, or a base64 one
 * checked as hex, a different digest when it is a wrong argument.
 *
 * @param expected - The digest to compare against, as text.
 * @param encoding - Its encoding.
 * @param name - The argument that carried it, for the error.
 * @returns {Uint8Array} Its bytes.
 */
export function assertExpected(
  expected: string,
  encoding: HashResult["encoding"],
  name = "expected",
): Uint8Array {
  const bytes = decodeExpected(expected, encoding);
  if (bytes !== undefined) return bytes;
  const form = encoding === "hex" ? "hex digit pairs, without a 0x prefix" : encoding;
  throw new InvalidOptionError(name, `${expected.length} characters`, `must be ${form}`);
}

/**
 * Compares a computed digest with an expected one in constant time.
 *
 * @param result - The computed hash, in the encoding the expected digest is written in.
 * @param expected - The expected digest as text.
 * @returns {boolean} Whether both name the same bytes.
 */
export function digestMatches(result: HashResult, expected: string): boolean {
  if (typeof result.digest !== "string") {
    throw new InvalidOptionError(
      "encoding",
      result.encoding,
      "compare a text digest: hex, base64 or base64url",
    );
  }
  const want = decodeExpected(expected, result.encoding);
  const have = decodeExpected(result.digest, result.encoding);
  if (want === undefined || have === undefined || want.length !== have.length) return false;
  // Or every byte's difference together, so the time does not tell where the first one is.
  let difference = 0;
  for (let i = 0; i < want.length; i++) difference |= want[i]! ^ have[i]!;
  return difference === 0;
}

/**
 * Lists the single option changes, HAVAL's `bits` or a KDF's `keyLength`, that give `length`.
 * Each one runs once on empty input, a KDF at its floor costs, and counts only if it's taken.
 *
 * @param hash - The algorithm.
 * @param options - The options the digest was computed with.
 * @param actual - Bytes those options give.
 * @param length - Bytes the expected digest has.
 * @returns {Array<Record<string, number | string>>} Each change that fits, one option apiece.
 */
export function lengthFixes(
  hash: Hash,
  options: Readonly<Record<string, unknown>>,
  actual: number,
  length: number,
): Array<Record<string, number | string>> {
  const info = hash.info();
  const candidates =
    hash instanceof Kdf
      ? keyLengthCandidates(info, options, actual, length)
      : choiceCandidates(info, options);
  const base = Object.fromEntries(
    Object.entries(options).filter(([name]) => name !== "rounds" && name !== "chain"),
  );
  const floor = hash instanceof Kdf ? floorCosts(info, options) : {};
  return candidates.filter((candidate) =>
    givesLength(hash, { ...base, ...floor, ...candidate }, length),
  );
}

/** The lowest cost each built-in KDF takes. No length, and no bound on one, depends on them. */
const FLOOR_COSTS: Readonly<Record<string, number>> = { N: 2, r: 1, p: 1, iterations: 1 };

/**
 * The costs a KDF probe runs at, so checking a `keyLength` never costs a second derivation.
 *
 * @param info - The KDF's metadata.
 * @param options - The options it ran with.
 * @returns {Record<string, number>} Its floor costs, Argon2's memory at 8 KiB a lane.
 */
function floorCosts(
  info: AlgorithmInfo,
  options: Readonly<Record<string, unknown>>,
): Record<string, number> {
  const declared = new Set(info.options.map((option) => option.name));
  const floor = Object.fromEntries(
    Object.entries(FLOOR_COSTS).filter(([name]) => declared.has(name)),
  );
  const lanes = info.options.find((option) => option.name === "parallelism");
  if (!declared.has("memory") || lanes === undefined) return floor;
  return { ...floor, memory: 8 * Number(options.parallelism ?? lanes.default) };
}

/**
 * Every value of an option with `choices` other than the one in use, one option apiece.
 *
 * @param info - The algorithm's metadata.
 * @param options - The options it ran with.
 * @returns {Array<Record<string, number | string>>} The candidates.
 */
function choiceCandidates(
  info: AlgorithmInfo,
  options: Readonly<Record<string, unknown>>,
): Array<Record<string, number | string>> {
  return info.options.flatMap((option) =>
    (option.choices ?? [])
      .filter((choice) => choice !== (options[option.name] ?? option.default))
      .map((choice) => ({ [option.name]: choice })),
  );
}

/**
 * Shifts `keyLength` by the difference, since EVP_BytesToKey puts its IV on top of the key.
 *
 * @param info - The KDF's metadata.
 * @param options - The options it ran with.
 * @param actual - Bytes they gave.
 * @param length - Bytes wanted.
 * @returns {Array<Record<string, number>>} The `keyLength` to try, or nothing without one.
 */
function keyLengthCandidates(
  info: AlgorithmInfo,
  options: Readonly<Record<string, unknown>>,
  actual: number,
  length: number,
): Array<Record<string, number>> {
  const declared = info.options.find((option) => option.name === "keyLength");
  if (declared === undefined) return [];
  const keyLength = Number(options.keyLength ?? declared.default) + length - actual;
  return keyLength >= 1 ? [{ keyLength }] : [];
}

/**
 * Whether the library takes these options and gives a digest of `length` bytes with them.
 *
 * @param hash - The algorithm.
 * @param options - The options to try.
 * @param length - Bytes wanted.
 * @returns {boolean} False for options it refuses, too.
 */
function givesLength(
  hash: Hash,
  options: Readonly<Record<string, unknown>>,
  length: number,
): boolean {
  try {
    const probe = { ...options, encoding: "binary" } as HashOptions;
    return hash.hash(new Uint8Array(0), probe).digestLength === length;
  } catch (error) {
    if (error instanceof HashError) return false;
    throw error;
  }
}

/**
 * Refuses to verify without an option drawn at random, such as a KDF salt: a fresh one can't match.
 *
 * @param info - The algorithm's metadata.
 * @param options - The options the digest is recomputed with.
 */
export function assertDrawnOptions(
  info: AlgorithmInfo,
  options: Readonly<Record<string, unknown>>,
): void {
  const missing = info.options.find(
    (option) =>
      option.random && (!Object.hasOwn(options, option.name) || options[option.name] === undefined),
  );
  if (missing) {
    throw new MissingOptionError(`${missing.name} (the one the expected digest was made with)`);
  }
}
