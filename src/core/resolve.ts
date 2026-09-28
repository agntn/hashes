import { hashFamilies } from "./algorithms.ts";
import { InvalidOptionError, UnknownAlgorithmError } from "./errors.ts";
import { algorithms, create, has } from "./registry.ts";
import type { Hash } from "./hash.ts";
import type { AlgorithmInfo } from "./types.ts";

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
 * @returns {Hash} The matching algorithm.
 */
export function resolveAlgorithm(preferred?: string): Hash {
  if (preferred) {
    const normalized = normalizeAlgorithmName(preferred);
    if (has(normalized)) return create(normalized);
  }
  throw new UnknownAlgorithmError(preferred ?? "(none)", algorithms());
}

/**
 * Reads the metadata of every registered algorithm, optionally of one family.
 *
 * @param family - Family to keep; omit for all.
 * @returns {AlgorithmInfo[]} The metadata in listing order.
 */
export function algorithmInfos(family?: string): AlgorithmInfo[] {
  if (family !== undefined && !(hashFamilies as readonly string[]).includes(family)) {
    throw new InvalidOptionError("family", family, `use one of ${hashFamilies.join(", ")}`);
  }
  return algorithms()
    .map((name) => create(name).info())
    .filter((info) => family === undefined || info.family === family);
}
