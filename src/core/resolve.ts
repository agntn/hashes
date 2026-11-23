import { hashCategories } from "./algorithms.ts";
import { type AlgorithmSuggestion, InvalidOptionError, UnknownAlgorithmError } from "./errors.ts";
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
 * Resolves a key, label or alias, case and punctuation aside: `SHA-256` finds `sha256`.
 *
 * @param preferred - Algorithm name or label.
 * @returns {Hash} The matching algorithm.
 */
export function resolveAlgorithm(preferred?: string): Hash {
  const key = preferred ? knownAlgorithm(preferred) : undefined;
  if (key !== undefined) return create(key);
  throw new UnknownAlgorithmError(
    preferred ?? "(none)",
    algorithms(),
    preferred ? suggestedAlgorithms(preferred) : [],
  );
}

/** Other names of a `family/variant`, compacted: CRC-32C is what most people call CRC-32/ISCSI. */
const VARIANT_ALIASES: Readonly<Record<string, string>> = {
  crc32c: "crc32/iscsi",
  crc32castagnoli: "crc32/iscsi",
};

/**
 * Points an unknown name at a `family/variant` option, a variant's catalogue alias or the keys it
 * begins, never at a typo's neighbour: `tiger2` is one letter off `tiger` and another digest.
 *
 * @param name - Name as typed.
 * @returns {AlgorithmSuggestion[]} The suggestions, empty when the name points nowhere.
 */
function suggestedAlgorithms(name: string): AlgorithmSuggestion[] {
  const alias = compactName(name);
  const variants = variantSuggestions(
    Object.hasOwn(VARIANT_ALIASES, alias) ? VARIANT_ALIASES[alias]! : name,
  );
  if (variants.length > 0) return variants;
  const wanted = compactName(name);
  return algorithms()
    .filter(
      (key) =>
        segmentPrefixes(key).includes(wanted) ||
        segmentPrefixes(create(key).info().label).includes(wanted),
    )
    .map((algorithm) => ({ algorithm }));
}

/**
 * Cuts a name into runs of letters and of digits and joins every leading run of them, so
 * `sha3-256` gives `sha`, `sha3` and `sha3256`, while `sha384` never gives `sha3`.
 *
 * @param name - Key or label.
 * @returns {string[]} The prefixes, compacted as `compactName` writes them.
 */
function segmentPrefixes(name: string): string[] {
  const segments = name.toLowerCase().match(/[a-z]+|\d+/g) ?? [];
  return segments.map((_, index) => segments.slice(0, index + 1).join(""));
}

/**
 * Reads `CRC-32/BZIP2` as the algorithm before the last slash and an option value after it.
 *
 * @param name - Name as typed.
 * @returns {AlgorithmSuggestion[]} One suggestion per option the value belongs to.
 */
function variantSuggestions(name: string): AlgorithmSuggestion[] {
  const slash = name.lastIndexOf("/");
  const algorithm = slash > 0 ? knownAlgorithm(name.slice(0, slash)) : undefined;
  if (algorithm === undefined) return [];
  const value = compactName(name.slice(slash + 1));
  return create(algorithm)
    .info()
    .options.flatMap((option) => {
      const choice = option.choices?.find((candidate) => compactName(String(candidate)) === value);
      return choice === undefined ? [] : [{ algorithm, parameters: { [option.name]: choice } }];
    });
}

/**
 * Looks a name up the way `resolveAlgorithm` does, without throwing.
 *
 * @param name - Name as typed.
 * @returns {string | undefined} The algorithm's key, or nothing when it resolves to none.
 */
function knownAlgorithm(name: string): string | undefined {
  const normalized = normalizeAlgorithmName(name);
  if (has(normalized)) return normalized;
  const spelled = spelledAlgorithms(name);
  if (spelled.length === 0) return aliasedAlgorithm(name);
  return spelled.length === 1 ? spelled[0] : undefined;
}

/** Names other code gives a key, compacted: Bitcoin Core calls hash256 sha256d. */
const KEY_ALIASES: Readonly<Record<string, string>> = {
  sha256d: "hash256",
};

/**
 * Reads a name as another code's name for a built-in key, once no key or label answers to it.
 *
 * @param name - Name as typed.
 * @returns {string | undefined} The key the alias stands for, or nothing.
 */
function aliasedAlgorithm(name: string): string | undefined {
  const compact = compactName(name);
  return Object.hasOwn(KEY_ALIASES, compact) ? KEY_ALIASES[compact] : undefined;
}

/**
 * Drops case and everything but letters and digits from a name.
 *
 * @param name - Key, label or name as typed.
 * @returns {string} The name as `spelledAlgorithms` compares it.
 */
function compactName(name: string): string {
  return name.toLowerCase().replaceAll(/[^a-z\d]/g, "");
}

/**
 * Finds the algorithms whose key or label matches a name once punctuation is gone.
 *
 * @param name - Name as typed.
 * @returns {string[]} Their keys; more than one makes the name ambiguous.
 */
function spelledAlgorithms(name: string): string[] {
  const wanted = compactName(name);
  if (wanted === "") return [];
  return algorithms().filter(
    (key) => compactName(key) === wanted || compactName(create(key).info().label) === wanted,
  );
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
