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
 * Resolves an algorithm by key or label, case and punctuation aside: `SHA-256` finds `sha256`.
 *
 * @param preferred - Algorithm name or label.
 * @returns {Hash} The matching algorithm.
 */
export function resolveAlgorithm(preferred?: string): Hash {
  if (preferred) {
    const normalized = normalizeAlgorithmName(preferred);
    if (has(normalized)) return create(normalized);
    const spelled = spelledAlgorithm(preferred);
    if (spelled !== undefined) return create(spelled);
  }
  throw new UnknownAlgorithmError(preferred ?? "(none)", algorithms());
}

/**
 * Drops case and everything but letters and digits from a name.
 *
 * @param name - Key, label or name as typed.
 * @returns {string} The name as `spelledAlgorithm` compares it.
 */
function compactName(name: string): string {
  return name.toLowerCase().replaceAll(/[^a-z\d]/g, "");
}

/**
 * Finds the one algorithm whose key or label matches a name once punctuation is gone.
 *
 * @param name - Name as typed.
 * @returns {string | undefined} The algorithm's key, or nothing when none or several match.
 */
function spelledAlgorithm(name: string): string | undefined {
  const wanted = compactName(name);
  if (wanted === "") return undefined;
  const matches = algorithms().filter(
    (key) => compactName(key) === wanted || compactName(create(key).info().label) === wanted,
  );
  return matches.length === 1 ? matches[0] : undefined;
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
      (wanted === undefined || familyKey(info.family) === wanted) &&
      (category === undefined || info.category === category),
  );
}

/**
 * Spells a family the way the filter compares it, so `SHA`, `sha` and ` Sha ` are one family.
 *
 * @param family - Family as typed or declared.
 * @returns {string} Trimmed and lowercased.
 */
function familyKey(family: string): string {
  return family.trim().toLowerCase();
}

/**
 * Checks that some registered algorithm declares the family, ignoring case.
 *
 * @param infos - Metadata of every registered algorithm.
 * @param family - Family as typed.
 * @returns {string} The family's comparison key.
 */
function knownFamily(infos: readonly AlgorithmInfo[], family: string): string {
  const wanted = familyKey(family);
  if (!infos.some((info) => familyKey(info.family) === wanted)) {
    const families = [...new Set(infos.map((info) => info.family))];
    throw new InvalidOptionError("family", family, `use one of ${families.join(", ")}`);
  }
  return wanted;
}
