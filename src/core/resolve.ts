import { hashCategories } from "./algorithms.ts";
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

/** Which algorithms `algorithmInfos` keeps; each field left out keeps them all. */
export interface AlgorithmFilter {
  /** Category to keep, one of `hashCategories`. */
  category?: string;
  /** Family to keep, such as `SHA` or `blake`; case does not matter. */
  family?: string;
}

/**
 * Reads the metadata of every registered algorithm, optionally of one category or family.
 *
 * @param filter - Category and family to keep; omit for all.
 * @returns {AlgorithmInfo[]} The metadata in listing order.
 */
export function algorithmInfos(filter: Readonly<AlgorithmFilter> = {}): AlgorithmInfo[] {
  const { category, family } = filter;
  if (category !== undefined && !(hashCategories as readonly string[]).includes(category)) {
    throw new InvalidOptionError("category", category, `use one of ${hashCategories.join(", ")}`);
  }
  const infos = algorithms().map((name) => create(name).info());
  const wanted = family === undefined ? undefined : knownFamily(infos, family);
  return infos.filter(
    (info) =>
      (wanted === undefined || info.family === wanted) &&
      (category === undefined || info.category === category),
  );
}

/**
 * Finds a family among the registered algorithms, ignoring case.
 *
 * @param infos - Metadata of every registered algorithm.
 * @param family - Family as typed.
 * @returns {string} The family as the algorithms spell it.
 */
function knownFamily(infos: readonly AlgorithmInfo[], family: string): string {
  const families = [...new Set(infos.map((info) => info.family))];
  const typed = family.trim().toLowerCase();
  const known = families.find((name) => name.toLowerCase() === typed);
  if (known === undefined) {
    throw new InvalidOptionError("family", family, `use one of ${families.join(", ")}`);
  }
  return known;
}
