import { InvalidOptionError, MissingOptionError } from "./errors.ts";
import type { AlgorithmInfo, HashResult } from "./types.ts";

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
 */
export function assertExpected(expected: string, encoding: HashResult["encoding"]): void {
  if (decodeExpected(expected, encoding) !== undefined) return;
  const form = encoding === "hex" ? "hex digit pairs, without a 0x prefix" : encoding;
  throw new InvalidOptionError("expected", `${expected.length} characters`, `must be ${form}`);
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
