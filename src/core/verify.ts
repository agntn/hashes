import { timingSafeEqual } from "node:crypto";
import { InvalidOptionError } from "./errors.ts";
import type { HashResult } from "./types.ts";

const HEX = /^(?:[0-9a-f]{2})*$/i;
const BASE64 = /^[A-Za-z0-9+/]*={0,2}$/;
const BASE64URL = /^[A-Za-z0-9_-]*$/;

/**
 * Decodes an expected digest written in the result's encoding. Hex ignores case; base64 and
 * base64url are case-sensitive, so they are compared as bytes, never as lowercased text.
 *
 * @param expected - The digest to compare against, as text.
 * @param encoding - Its encoding.
 * @returns {Buffer | undefined} Its bytes, or undefined when it is not valid in that encoding.
 */
function decodeExpected(expected: string, encoding: HashResult["encoding"]): Buffer | undefined {
  const trimmed = expected.trim();
  if (encoding === "hex") return HEX.test(trimmed) ? Buffer.from(trimmed, "hex") : undefined;
  if (encoding === "base64")
    return BASE64.test(trimmed) ? Buffer.from(trimmed, "base64") : undefined;
  if (encoding === "base64url") {
    return BASE64URL.test(trimmed) ? Buffer.from(trimmed, "base64url") : undefined;
  }
  throw new InvalidOptionError(
    "encoding",
    encoding,
    "compare a text digest: hex, base64 or base64url",
  );
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
  const have = Buffer.from(result.digest, result.encoding);
  return want !== undefined && want.length === have.length && timingSafeEqual(want, have);
}
