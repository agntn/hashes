import { UnknownAlgorithmError } from "./errors.ts";
import { algorithms, create, has } from "./registry.ts";
import type { HashAlgorithm } from "./types.ts";

/**
 * Normalizes a user-typed algorithm name: lowercase, with spaces and underscores as hyphens,
 * so `SHA3_256` and `sha3 256` find `sha3-256`.
 *
 * @param name - Name as typed.
 * @returns {string} The registry spelling.
 */
export function normalizeAlgorithmName(name: string): string {
  return name
    .trim()
    .toLowerCase()
    .replaceAll(/[\s_]+/g, "-");
}

/**
 * Resolves a hash algorithm from a user-typed name.
 *
 * @param preferred - Algorithm name, normalized by `normalizeAlgorithmName`.
 * @returns {HashAlgorithm} The matching algorithm.
 */
export function resolveAlgorithm(preferred?: string): HashAlgorithm {
  if (preferred) {
    const normalized = normalizeAlgorithmName(preferred);
    if (has(normalized)) return create(normalized);
  }
  throw new UnknownAlgorithmError(preferred ?? "(none)", algorithms());
}
