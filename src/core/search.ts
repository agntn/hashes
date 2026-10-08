/**
 * Finds the transform behind a digest: which words, in which order and case, joined how and
 * hashed with what, give it. Puzzles make passwords and keys this way (#100).
 */

import {
  SEARCH_CASES,
  SEARCH_CHAINS,
  SEARCH_JOINERS,
} from "../../packages/shared/tool-contract.ts";
import { toBytes } from "./digest.ts";
import { HashError, InvalidOptionError, quoted } from "./errors.ts";
import { algorithms, create } from "./registry.ts";
import { resolveAlgorithm } from "./resolve.ts";
import { lengthChoices } from "./identify.ts";
import type { Hash } from "./hash.ts";
import type { HashOptions } from "./types.ts";

export { SEARCH_CASES, SEARCH_CHAINS, SEARCH_JOINERS };
export type SearchCase = (typeof SEARCH_CASES)[number];
export type SearchChain = (typeof SEARCH_CHAINS)[number];

/** How often `onProgress` hears from a running search, in hashes. */
const PROGRESS_INTERVAL = 100_000;

/** What to try. Every list left out tries all its values; the words are the only requirement. */
export interface SearchDigestOptions {
  /** The candidate words, each used at most once per combination. */
  readonly words: readonly string[];
  /** Fewest words in a combination. Default: 1. */
  readonly minWords?: number;
  /** Most words in a combination. Default: all of them. */
  readonly maxWords?: number;
  /** What goes between two words. Default: `SEARCH_JOINERS`. */
  readonly joiners?: readonly string[];
  /** Default: every one of `SEARCH_CASES`. */
  readonly cases?: readonly SearchCase[];
  /** Default: every registered fixed-length digest as long as the target. */
  readonly algorithms?: readonly string[];
  /** Deepest repetition: 2 hashes the digest again, as each chain says. Default: 1. */
  readonly rounds?: number;
  /** Default: every one of `SEARCH_CHAINS`. Ignored at one round. */
  readonly chains?: readonly SearchChain[];
  /** Most hashes to compute before giving up. Default: no limit. */
  readonly limit?: number;
  /** Most bytes to hash, texts and chained digests alike, before giving up. Default: no limit. */
  readonly byteLimit?: number;
  /** Hears the running count: once at 0 with the total, then every 100,000 hashes. */
  readonly onProgress?: (tried: number, total: number) => void;
}

/** What a search covered, its lists with duplicates gone. */
export interface SearchScope {
  readonly words: readonly string[];
  readonly minWords: number;
  readonly maxWords: number;
  readonly joiners: readonly string[];
  readonly cases: readonly SearchCase[];
  readonly algorithms: readonly string[];
  readonly rounds: number;
  readonly chains: readonly SearchChain[];
  /** Algorithms that hash UTF-8 text only, such as NTLM, so no round hashes bytes with them. */
  readonly textOnly: readonly string[];
}

/** The transform that gives the digest. */
export interface DigestRecipe {
  /** The words in the order they were joined, as given. */
  readonly words: readonly string[];
  readonly joiner: string;
  readonly case: SearchCase;
  /** The text that was hashed, after joining and casing. */
  readonly input: string;
  readonly algorithm: string;
  /** The option value that set the digest's length, such as `variant: bzip2`; absent by default. */
  readonly parameters?: Readonly<Record<string, number | string>>;
  readonly rounds: number;
  /** What each round after the first hashed; absent at one round. */
  readonly chain?: SearchChain;
}

/** How a search ended. */
export interface DigestSearch {
  /** Hashes the scope holds. */
  readonly total: number;
  /** Hashes computed before it ended. */
  readonly tried: number;
  /** Set when a candidate gave the digest. */
  readonly recipe?: DigestRecipe;
  /** Whether the limit ended it before a match or the end of the scope. */
  readonly stopped: boolean;
  readonly scope: SearchScope;
}

/** One digest of a list and what explained it. */
export interface DigestSearchItem {
  /** The digest in lowercase hex. */
  readonly digest: string;
  /** Set when a candidate gave this digest. */
  readonly recipe?: DigestRecipe;
  /** What the search covered for it: the algorithms of its length. */
  readonly scope: SearchScope;
}

/** How a search for several digests at once ended. */
export interface DigestSearchBatch {
  /** Hashes the scope holds, every length of the list together. */
  readonly total: number;
  /** Hashes computed before it ended. */
  readonly tried: number;
  /** Whether the limit ended it before every digest had a recipe or the scope ran out. */
  readonly stopped: boolean;
  /** One per digest, in the order given. */
  readonly items: readonly DigestSearchItem[];
}

/** One text to hash and how it was made. */
interface Candidate {
  readonly words: readonly string[];
  readonly joiner: string;
  readonly case: SearchCase;
  readonly input: string;
}

/**
 * Cases one word.
 *
 * @param word - The word as given.
 * @param form - The case to put it in.
 * @returns {string} The cased word.
 */
function caseWord(word: string, form: SearchCase): string {
  if (form === "lower") return word.toLowerCase();
  if (form === "upper") return word.toUpperCase();
  if (form === "title") {
    const first = String.fromCodePoint(word.codePointAt(0)!);
    return first.toUpperCase() + word.slice(first.length).toLowerCase();
  }
  return word;
}

/**
 * Labels values by first appearance, so equal values share a label: `a, b, a` gives `0,1,0`.
 *
 * @param values - One value per case.
 * @returns {string} The labels, comma-separated.
 */
function partition(values: readonly string[]): string {
  const labels: string[] = [];
  return values
    .map((value) => {
      if (!labels.includes(value)) labels.push(value);
      return labels.indexOf(value);
    })
    .join(",");
}

/**
 * Splits the cases where two partitions split them: the cases a combination cannot tell apart.
 *
 * @param a - One partition.
 * @param b - The other.
 * @returns {string} Their meet.
 */
function meet(a: string, b: string): string {
  const right = b.split(",");
  return partition(a.split(",").map((label, index) => `${label}/${right[index]}`));
}

/**
 * Counts the cased combinations of each size: the distinct texts before ordering and joining.
 *
 * Two cases give the same text for a combination when they give the same text for each of its
 * words, so each word splits the cases into groups, and a combination gives one text per group
 * of the meet of its words' splits. Counting combinations per split avoids listing them.
 *
 * @param words - The distinct words.
 * @param cases - The distinct cases.
 * @param maxWords - Largest combination.
 * @returns {bigint[]} At index k, the cased combinations of k words, before ordering and joining.
 */
function casedCombinations(
  words: readonly string[],
  cases: readonly SearchCase[],
  maxWords: number,
): bigint[] {
  const bySize: Map<string, bigint>[] = [new Map([[partition(cases.map(() => "")), 1n]])];
  for (const word of words) {
    const split = partition(cases.map((form) => caseWord(word, form)));
    for (let size = Math.min(bySize.length, maxWords) - 1; size >= 0; size--) {
      const next = (bySize[size + 1] ??= new Map());
      for (const [key, count] of bySize[size]!) {
        const joined = meet(key, split);
        next.set(joined, (next.get(joined) ?? 0n) + count);
      }
    }
  }
  return bySize.map((splits) =>
    [...splits].reduce(
      (sum, [key, count]) => sum + count * BigInt(new Set(key.split(",")).size),
      0n,
    ),
  );
}

/**
 * Counts the texts a scope makes, a text two splits make once per split.
 *
 * @param scope - What the search covers.
 * @returns {bigint} Every text it hashes.
 */
function textCount(scope: SearchScope): bigint {
  const combinations = casedCombinations(scope.words, scope.cases, scope.maxWords);
  let texts = 0n;
  let orderings = 1n;
  for (let size = 1; size <= scope.maxWords; size++) {
    orderings *= BigInt(size);
    if (size < scope.minWords) continue;
    const joiners = BigInt(size === 1 ? 1 : scope.joiners.length);
    texts += (combinations[size] ?? 0n) * orderings * joiners;
  }
  return texts;
}

/**
 * Counts the hashes one text costs: each algorithm once, then each of its chains round by round.
 *
 * @param scope - What the search covers for one digest length.
 * @returns {bigint} The hashes per text.
 */
function hashesPerText(scope: SearchScope): bigint {
  const hashes = scope.algorithms.reduce((sum, label) => {
    const chains = chainsFor(scope, scope.textOnly.includes(label)).length;
    return sum + 1 + (scope.rounds > 1 ? chains * (scope.rounds - 1) : 0);
  }, 0);
  return BigInt(hashes);
}

/**
 * Counts the hashes a search holds over its lengths, refusing a total too large to be exact.
 *
 * @param scopes - What the search covers, per digest length.
 * @returns {number} Every hash it would compute without a match.
 */
function searchSize(scopes: readonly SearchScope[]): number {
  const [first] = scopes;
  const perText = scopes.reduce((sum, scope) => sum + hashesPerText(scope), 0n);
  const total = textCount(first!) * perText;
  if (total > BigInt(Number.MAX_SAFE_INTEGER)) {
    throw new InvalidOptionError(
      "maxWords",
      first!.maxWords,
      `makes more than ${Number.MAX_SAFE_INTEGER} hashes, lower it to search the smaller combinations`,
    );
  }
  return Number(total);
}

/**
 * Lists every way to pick `size` of `count` indices, in increasing order.
 *
 * @param count - How many to pick from.
 * @param size - How many to pick.
 * @yields {readonly number[]} The picked indices.
 */
function* combinationsOf(count: number, size: number): Generator<readonly number[]> {
  const picked = Array.from({ length: size }, (_, index) => index);
  while (true) {
    yield [...picked];
    let at = size - 1;
    while (at >= 0 && picked[at] === count - size + at) at--;
    if (at < 0) return;
    picked[at]!++;
    for (let after = at + 1; after < size; after++) picked[after] = picked[after - 1]! + 1;
  }
}

/**
 * Lists every order of the given items, in lexicographic order of their positions.
 *
 * @param items - The items to order.
 * @yields {readonly string[]} One ordering.
 */
function* orderingsOf<T>(items: readonly T[]): Generator<readonly T[]> {
  const order = items.map((_, index) => index);
  while (true) {
    yield order.map((index) => items[index]!);
    let pivot = order.length - 2;
    while (pivot >= 0 && order[pivot]! > order[pivot + 1]!) pivot--;
    if (pivot < 0) return;
    let swap = order.length - 1;
    while (order[swap]! < order[pivot]!) swap--;
    [order[pivot], order[swap]] = [order[swap]!, order[pivot]!];
    order.splice(pivot + 1, Infinity, ...order.slice(pivot + 1).reverse());
  }
}

/**
 * Lists the cases that give different texts for one combination, each with its cased words.
 *
 * @param words - The combination, as given.
 * @param cases - The cases to try.
 * @returns {Array<readonly [SearchCase, readonly string[]]>} The first case of each distinct text.
 */
function distinctCases(
  words: readonly string[],
  cases: readonly SearchCase[],
): Array<readonly [SearchCase, readonly string[]]> {
  const seen = new Set<string>();
  const found: Array<readonly [SearchCase, readonly string[]]> = [];
  for (const form of cases) {
    const cased = words.map((word) => caseWord(word, form));
    const key = JSON.stringify(cased);
    if (seen.has(key)) continue;
    seen.add(key);
    found.push([form, cased]);
  }
  return found;
}

/**
 * Lists the texts of one combination: each distinct case, each order, each joiner.
 *
 * @param picked - The combination, as given.
 * @param scope - What the search covers.
 * @yields {Candidate} One text with its recipe.
 */
function* textsOf(picked: readonly string[], scope: SearchScope): Generator<Candidate> {
  const joiners = picked.length === 1 ? scope.joiners.slice(0, 1) : scope.joiners;
  for (const [form, cased] of distinctCases(picked, scope.cases)) {
    const positions = cased.map((_, index) => index);
    for (const order of orderingsOf(positions)) {
      const words = order.map((index) => picked[index]!);
      const ordered = order.map((index) => cased[index]!);
      for (const joiner of joiners) {
        yield { words, joiner, case: form, input: ordered.join(joiner) };
      }
    }
  }
}

/**
 * Lists every text a scope makes, the smallest combinations first. A text two splits make, `ab`
 * alone and `a` + `b` with no joiner, comes once per split, and `total` counts both.
 *
 * @param scope - What the search covers.
 * @yields {Candidate} One text with its recipe.
 */
function* candidatesOf(scope: SearchScope): Generator<Candidate> {
  for (let size = scope.minWords; size <= scope.maxWords; size++) {
    for (const indices of combinationsOf(scope.words.length, size)) {
      yield* textsOf(
        indices.map((index) => scope.words[index]!),
        scope,
      );
    }
  }
}

/**
 * Compares two digests.
 *
 * @param a - One digest.
 * @param b - The other.
 * @returns {boolean} Whether they hold the same bytes.
 */
function sameBytes(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

/**
 * Reads a whole number option.
 *
 * @param name - The option, for the error.
 * @param value - Its value.
 * @param minimum - Smallest value.
 * @param maximum - Largest value.
 * @returns {number} The value.
 */
function wholeNumber(name: string, value: number, minimum: number, maximum: number): number {
  if (!Number.isInteger(value) || value < minimum || value > maximum) {
    throw new InvalidOptionError(
      name,
      value,
      `must be a whole number from ${minimum} to ${maximum}`,
    );
  }
  return value;
}

/**
 * Removes duplicates from a list option, refusing an empty one or a value outside its choices.
 *
 * @param name - The option, for the error.
 * @param values - The values as given.
 * @param choices - The values it takes, when it is a closed set.
 * @returns {T[]} The distinct values, in the order given.
 */
function distinct<T extends string>(
  name: string,
  values: readonly T[],
  choices?: readonly string[],
): T[] {
  if (values.length === 0)
    throw new InvalidOptionError(name, "(empty)", "needs at least one value");
  const wrong =
    choices === undefined ? undefined : values.find((value) => !choices.includes(value));
  if (wrong !== undefined) {
    throw new InvalidOptionError(name, wrong, `use any of ${choices!.join(", ")}`);
  }
  return [...new Set(values)];
}

/**
 * Reads the words: at least one, none empty, none twice.
 *
 * @param words - The words as given.
 * @returns {string[]} The words.
 */
function wordList(words: readonly string[]): string[] {
  if (words.length === 0)
    throw new InvalidOptionError("words", "(empty)", "needs at least one word");
  if (words.includes("")) throw new InvalidOptionError("words", '""', "a word must not be empty");
  const repeated = words.find((word, index) => words.indexOf(word) !== index);
  if (repeated !== undefined) {
    throw new InvalidOptionError(
      "words",
      repeated,
      "is listed twice; each word is used at most once",
    );
  }
  return [...words];
}

/** One algorithm as the search runs it: a registered digest, or one of its option values. */
interface Reading {
  readonly hash: Hash;
  readonly parameters?: Readonly<Record<string, number | string>>;
  readonly label: string;
  /** Set when the algorithm refuses bytes that are not UTF-8, as NTLM does. */
  readonly textOnly: boolean;
}

/**
 * Lists the chains a search runs with one algorithm: all of them, less `bytes` for text only.
 *
 * @param scope - What the search covers.
 * @param textOnly - Whether the algorithm hashes UTF-8 text only.
 * @returns {readonly SearchChain[]} The chains.
 */
function chainsFor(scope: SearchScope, textOnly: boolean): readonly SearchChain[] {
  return textOnly ? scope.chains.filter((chain) => chain !== "bytes") : scope.chains;
}

/**
 * Tells whether an algorithm refuses bytes that are not UTF-8, by hashing one lone 0xff.
 *
 * @param hash - The algorithm.
 * @param parameters - The option value it runs with.
 * @returns {boolean} Whether it hashes text only.
 */
function hashesTextOnly(
  hash: Hash,
  parameters: Readonly<Record<string, number | string>> | undefined,
): boolean {
  try {
    hash.hash(Uint8Array.of(0xff), { ...parameters, encoding: "binary" } as HashOptions);
    return false;
  } catch (error) {
    if (error instanceof HashError) return true;
    throw error;
  }
}

/**
 * Lists the readings of one digest that make `length` bytes: its default, and each option value
 * that changes its length, the way `identifyDigest` reads CRC-32/BZIP2 and XXH32.
 *
 * @param hash - The algorithm.
 * @param length - The target's length in bytes.
 * @returns {Reading[]} The readings that fit.
 */
function readingsOf(hash: Hash, length: number): Reading[] {
  const info = hash.info();
  const name = hash.name();
  const found: Reading[] =
    info.digestLength === length
      ? [{ hash, label: name, textOnly: hashesTextOnly(hash, undefined) }]
      : [];
  for (const { option, choice } of lengthChoices(name, info, length)) {
    const parameters = { [option]: choice };
    const label = `${name} ${option} ${choice}`;
    found.push({ hash, parameters, label, textOnly: hashesTextOnly(hash, parameters) });
  }
  return found;
}

/**
 * Writes a digest length the way an error names it.
 *
 * @param length - The length in bytes.
 * @returns {string} `1 byte` or `<n> bytes`.
 */
function byteSize(length: number): string {
  return length === 1 ? "1 byte" : `${length} bytes`;
}

/**
 * Lists every registered fixed-length digest for each length, with the option values that fit.
 *
 * @param lengths - The distinct digest lengths, in bytes.
 * @param names - The digest each length is named by in an error.
 * @returns {Reading[][]} The readings of each length, in the order of `lengths`.
 */
function defaultReadings(lengths: readonly number[], names: readonly string[]): Reading[][] {
  const fixed = algorithms()
    .map((name) => create(name))
    .filter((hash) => isFixed(hash));
  return lengths.map((length, index) => {
    const fitting = fixed.flatMap((hash) => readingsOf(hash, length));
    if (fitting.length === 0) {
      throw new InvalidOptionError(
        names[index]!,
        byteSize(length),
        "no registered digest is that long",
      );
    }
    return fitting;
  });
}

/**
 * Reads the named algorithms per length; each must fit some length, and each length needs one.
 *
 * @param named - The algorithms as given.
 * @param lengths - The distinct digest lengths, in bytes.
 * @param names - The digest each length is named by in an error.
 * @returns {Reading[][]} The readings of each length, in the order of `lengths`.
 */
function namedReadings(
  named: readonly string[],
  lengths: readonly number[],
  names: readonly string[],
): Reading[][] {
  const resolved = distinct("algorithms", named).map((name) => resolveAlgorithm(name));
  const unique = [...new Map(resolved.map((hash) => [hash.name(), hash])).values()];
  const fits = unique.map((hash) => {
    if (!isFixed(hash)) {
      throw new InvalidOptionError("algorithms", hash.name(), "is no fixed-length digest");
    }
    const perLength = lengths.map((length) => readingsOf(hash, length));
    if (perLength.every((fitting) => fitting.length === 0)) {
      const digest =
        lengths.length === 1 ? `the digest is ${lengths[0]}` : "no digest of the list is that long";
      throw new InvalidOptionError(
        "algorithms",
        hash.name(),
        `makes ${hash.info().digestLength} bytes and ${digest}`,
      );
    }
    return perLength;
  });
  return lengths.map((length, index) => {
    const fitting = fits.flatMap((perLength) => perLength[index]!);
    if (fitting.length === 0) {
      throw new InvalidOptionError(
        names[index]!,
        byteSize(length),
        "none of the algorithms makes that many bytes",
      );
    }
    return fitting;
  });
}

/**
 * Refuses two words that one of the cases turns into the same text: each would make the other's
 * texts again, which the exact total cannot see.
 *
 * @param words - The distinct words.
 * @param cases - The cases to try.
 */
function assertDistinctCased(words: readonly string[], cases: readonly SearchCase[]): void {
  for (const form of cases) {
    const seen = new Map<string, string>();
    for (const word of words) {
      const cased = caseWord(word, form);
      const earlier = seen.get(cased);
      if (earlier !== undefined) {
        throw new InvalidOptionError(
          "words",
          word,
          `gives the same text as ${quoted(earlier)} in case ${form}; drop one, or leave ${form} out of cases`,
        );
      }
      seen.set(cased, word);
    }
  }
}

/**
 * Tells a fixed-length digest from a KDF: only the former takes `rounds`.
 *
 * @param hash - The algorithm.
 * @returns {boolean} Whether the search can repeat it.
 */
function isFixed(hash: Hash): boolean {
  return hash.info().options.some((option) => option.name === "rounds");
}

/** The digests of one length, the algorithms that make that many bytes, and what they cover. */
interface Group {
  readonly scope: SearchScope;
  readonly readings: readonly Reading[];
  /** Where its digests sit in the list. */
  readonly targets: readonly number[];
}

/**
 * Checks the digests, refusing an empty one.
 *
 * @param targets - The digests.
 * @returns {string[]} The name each digest goes by in an error: `digest`, or `digest 2` in a list.
 */
function digestNames(targets: readonly Uint8Array[]): string[] {
  const names =
    targets.length === 1 ? ["digest"] : targets.map((_, index) => `digest ${index + 1}`);
  targets.forEach((target, index) => {
    if (target.length === 0)
      throw new InvalidOptionError(names[index]!, "(empty)", "needs at least one byte");
  });
  return names;
}

/**
 * Checks the options and fills in the defaults, one group per digest length.
 *
 * @param targets - The digests.
 * @param options - The caller's options.
 * @returns {Group[]} The groups, in the order their lengths first appear.
 */
function searchGroups(targets: readonly Uint8Array[], options: SearchDigestOptions): Group[] {
  const names = digestNames(targets);
  const words = wordList(options.words);
  const maxWords = wholeNumber("maxWords", options.maxWords ?? words.length, 1, words.length);
  const minWords = wholeNumber("minWords", options.minWords ?? 1, 1, maxWords);
  const lengths = [...new Set(targets.map((target) => target.length))];
  const firsts = lengths.map((length) => targets.findIndex((target) => target.length === length));
  const lengthNames = firsts.map((first) => names[first]!);
  const readings =
    options.algorithms === undefined
      ? defaultReadings(lengths, lengthNames)
      : namedReadings(options.algorithms, lengths, lengthNames);
  const cases = distinct("cases", options.cases ?? SEARCH_CASES, SEARCH_CASES);
  assertDistinctCased(words, cases);
  const shared = {
    words,
    minWords,
    maxWords,
    joiners: distinct("joiners", options.joiners ?? SEARCH_JOINERS),
    cases,
    rounds: wholeNumber("rounds", options.rounds ?? 1, 1, Number.MAX_SAFE_INTEGER),
    chains: distinct("chains", options.chains ?? SEARCH_CHAINS, SEARCH_CHAINS),
  };
  return lengths.map((length, index) => {
    const fitting = readings[index]!;
    const scope: SearchScope = {
      ...shared,
      algorithms: fitting.map((reading) => reading.label),
      textOnly: fitting.filter((reading) => reading.textOnly).map((reading) => reading.label),
    };
    const indices = targets.flatMap((target, at) => (target.length === length ? [at] : []));
    return { scope, readings: fitting, targets: indices };
  });
}

/**
 * Hashes a digest again as a chain says.
 *
 * @param reading - The algorithm.
 * @param digest - The previous round's digest.
 * @param chain - What to hash of it.
 * @returns {Uint8Array} The next round's digest.
 */
function nextRound(reading: Reading, digest: Uint8Array, chain: SearchChain): Uint8Array {
  if (chain === "bytes") return digestOf(reading, digest);
  const hex = digest.toHex();
  return digestOf(reading, toBytes(chain === "hex" ? hex : hex.toUpperCase()));
}

/**
 * Hashes bytes to raw digest bytes.
 *
 * @param reading - The algorithm, with the option value it runs with.
 * @param bytes - What to hash.
 * @returns {Uint8Array} The digest.
 */
function digestOf(reading: Reading, bytes: Uint8Array): Uint8Array {
  const options = { ...reading.parameters, encoding: "binary" } as HashOptions;
  const { digest } = reading.hash.hash(bytes, options);
  if (!(digest instanceof Uint8Array)) throw new TypeError(`${reading.label} returned no bytes`);
  return digest;
}

/**
 * Writes the recipe a candidate makes with one algorithm.
 *
 * @param candidate - The text and how it was made.
 * @param reading - The algorithm.
 * @param rounds - How many times it was hashed.
 * @param chain - What each round after the first hashed.
 * @returns {DigestRecipe} The recipe.
 */
function recipeOf(
  candidate: Candidate,
  reading: Reading,
  rounds: number,
  chain?: SearchChain,
): DigestRecipe {
  const { parameters } = reading;
  return {
    ...candidate,
    algorithm: reading.hash.name(),
    ...(parameters && { parameters }),
    rounds,
    ...(chain && { chain }),
  };
}

/** How a run ended, before it is told per digest. */
interface SearchRun {
  readonly total: number;
  readonly tried: number;
  readonly stopped: boolean;
  /** One per digest, in the order given. */
  readonly recipes: ReadonlyArray<DigestRecipe | undefined>;
}

/** One pass over the texts for every digest, each hash held against all targets of its length. */
class Search {
  readonly #targets: readonly Uint8Array[];
  readonly #groups: readonly Group[];
  readonly #total: number;
  readonly #limit: number;
  readonly #byteLimit: number;
  readonly #onProgress: SearchDigestOptions["onProgress"];
  readonly #recipes: Array<DigestRecipe | undefined>;
  /** Digests of each group still without a recipe. */
  readonly #pending: number[];
  #left: number;
  #tried = 0;
  #bytes = 0;

  constructor(
    targets: readonly Uint8Array[],
    groups: readonly Group[],
    options: SearchDigestOptions,
  ) {
    this.#targets = targets;
    this.#groups = groups;
    this.#total = searchSize(groups.map((group) => group.scope));
    this.#limit = options.limit ?? Infinity;
    this.#byteLimit = options.byteLimit ?? Infinity;
    this.#onProgress = options.onProgress;
    this.#recipes = targets.map(() => undefined);
    this.#pending = groups.map((group) => group.targets.length);
    this.#left = targets.length;
    this.#onProgress?.(0, this.#total);
  }

  /**
   * Tries every candidate until each digest has a recipe, the scope runs out or the limit ends it.
   *
   * @returns {SearchRun} The count and the recipes.
   */
  run(): SearchRun {
    for (const candidate of candidatesOf(this.#groups[0]!.scope)) {
      for (let index = 0; index < this.#groups.length; index++) {
        if (this.#group(candidate, index) === "limit") return this.#ended(true);
        if (this.#left === 0) return this.#ended(false);
      }
    }
    return this.#ended(false);
  }

  /**
   * Writes how the run ended.
   *
   * @param stopped - Whether the limit ended it.
   * @returns {SearchRun} The count and the recipes.
   */
  #ended(stopped: boolean): SearchRun {
    return { total: this.#total, tried: this.#tried, stopped, recipes: this.#recipes };
  }

  /**
   * Hashes one text with every algorithm of one group, while the group has digests left.
   *
   * @param candidate - The text and its recipe.
   * @param index - The group.
   * @returns {"limit" | undefined} `limit` when the limit ended it.
   */
  #group(candidate: Candidate, index: number): "limit" | undefined {
    for (const reading of this.#groups[index]!.readings) {
      if (this.#pending[index] === 0) return undefined;
      if (this.#candidate(candidate, index, reading) === "limit") return "limit";
    }
    return undefined;
  }

  /**
   * Counts one hash about to be computed.
   *
   * @param bytes - How many bytes it hashes.
   * @returns {boolean} Whether both limits still allow it.
   */
  #next(bytes: number): boolean {
    if (this.#tried >= this.#limit || this.#bytes + bytes > this.#byteLimit) return false;
    this.#tried++;
    this.#bytes += bytes;
    if (this.#tried % PROGRESS_INTERVAL === 0) this.#onProgress?.(this.#tried, this.#total);
    return true;
  }

  /**
   * Tells whether a digest equals one of the group's digests still without a recipe.
   *
   * @param index - The group.
   * @param digest - What a candidate hashed to.
   * @returns {boolean} Whether it explains one.
   */
  #hits(index: number, digest: Uint8Array): boolean {
    return this.#groups[index]!.targets.some(
      (at) => this.#recipes[at] === undefined && sameBytes(digest, this.#targets[at]!),
    );
  }

  /**
   * Gives a recipe to every digest of the group that it explains.
   *
   * @param index - The group.
   * @param digest - What the recipe hashes to.
   * @param recipe - The recipe.
   */
  #record(index: number, digest: Uint8Array, recipe: DigestRecipe): void {
    for (const at of this.#groups[index]!.targets) {
      if (this.#recipes[at] !== undefined || !sameBytes(digest, this.#targets[at]!)) continue;
      this.#recipes[at] = recipe;
      this.#pending[index]!--;
      this.#left--;
    }
  }

  /**
   * Hashes one text with one algorithm, then again round after round in each chain.
   *
   * @param candidate - The text and its recipe.
   * @param index - The group.
   * @param reading - The algorithm.
   * @returns {"limit" | undefined} `limit` when the limit ended it.
   */
  #candidate(candidate: Candidate, index: number, reading: Reading): "limit" | undefined {
    const input = toBytes(candidate.input);
    if (!this.#next(input.length)) return "limit";
    const first = digestOf(reading, input);
    if (this.#hits(index, first)) this.#record(index, first, recipeOf(candidate, reading, 1));
    const { scope } = this.#groups[index]!;
    if (scope.rounds === 1) return undefined;
    for (const chain of chainsFor(scope, reading.textOnly)) {
      if (this.#pending[index] === 0) return undefined;
      if (this.#chain(candidate, index, reading, first, chain) === "limit") return "limit";
    }
    return undefined;
  }

  /**
   * Hashes a digest again round after round in one chain, while the group has digests left.
   *
   * @param candidate - The text and its recipe.
   * @param index - The group.
   * @param reading - The algorithm.
   * @param first - The first round's digest.
   * @param chain - What each next round hashes.
   * @returns {"limit" | undefined} `limit` when the limit ended it.
   */
  #chain(
    candidate: Candidate,
    index: number,
    reading: Reading,
    first: Uint8Array,
    chain: SearchChain,
  ): "limit" | undefined {
    const { rounds } = this.#groups[index]!.scope;
    let digest = first;
    for (let round = 2; round <= rounds && this.#pending[index]! > 0; round++) {
      if (!this.#next(chain === "bytes" ? digest.length : digest.length * 2)) return "limit";
      digest = nextRound(reading, digest, chain);
      if (this.#hits(index, digest)) {
        this.#record(index, digest, recipeOf(candidate, reading, round, chain));
      }
    }
    return undefined;
  }
}

/**
 * Checks the limits and runs a search over the digests.
 *
 * @param targets - The digests.
 * @param options - The words and what to try with them.
 * @returns {{ run: SearchRun; groups: Group[] }} How it ended, and the groups it ran.
 */
function runSearch(
  targets: readonly Uint8Array[],
  options: SearchDigestOptions,
): { run: SearchRun; groups: Group[] } {
  if (options.limit !== undefined) wholeNumber("limit", options.limit, 1, Number.MAX_SAFE_INTEGER);
  if (options.byteLimit !== undefined) {
    wholeNumber("byteLimit", options.byteLimit, 1, Number.MAX_SAFE_INTEGER);
  }
  const groups = searchGroups(targets, options);
  return { run: new Search(targets, groups, options).run(), groups };
}

/**
 * Checks a list of digests: at least one, each a `Uint8Array`.
 *
 * @param targets - The digests as given.
 * @returns {Uint8Array[]} The digests.
 */
function targetList(targets: readonly unknown[]): Uint8Array[] {
  if (targets.length === 0)
    throw new InvalidOptionError("digest", "(empty)", "needs at least one digest");
  return targets.map((target, index) => {
    if (target instanceof Uint8Array) return target;
    throw new InvalidOptionError(`digest ${index + 1}`, typeof target, "must be a Uint8Array");
  });
}

/**
 * Tries the words in every subset and order, joined, cased and hashed as UTF-8, smallest
 * combinations first, until each digest has a recipe or the limit ends the search.
 *
 * @param target - The digest, as bytes, or a list of them.
 * @param options - The words and what to try with them.
 * @returns {DigestSearch} How many hashes the scope held and were tried, and the recipe on a match,
 * one item per digest for a list.
 */
export function searchDigest(target: Uint8Array, options: SearchDigestOptions): DigestSearch;
export function searchDigest(
  targets: readonly Uint8Array[],
  options: SearchDigestOptions,
): DigestSearchBatch;
export function searchDigest(
  target: Uint8Array | readonly Uint8Array[],
  options: SearchDigestOptions,
): DigestSearch | DigestSearchBatch {
  if (!Array.isArray(target)) {
    const { run, groups } = runSearch([target as Uint8Array], options);
    const [recipe] = run.recipes;
    const { total, tried, stopped } = run;
    return { total, tried, ...(recipe && { recipe }), stopped, scope: groups[0]!.scope };
  }
  const targets = targetList(target);
  const { run, groups } = runSearch(targets, options);
  const items = targets.map((digest, at) => {
    const recipe = run.recipes[at];
    const { scope } = groups.find((group) => group.targets.includes(at))!;
    return { digest: digest.toHex(), ...(recipe && { recipe }), scope };
  });
  return { total: run.total, tried: run.tried, stopped: run.stopped, items };
}

/**
 * Writes a list of words or joiners the way the answer quotes them.
 *
 * @param values - The values.
 * @returns {string} Each value in quotes, comma-separated.
 */
function quotedList(values: readonly string[]): string {
  return values.map((value) => quoted(value)).join(", ");
}

/**
 * Describes a recipe in one line: the algorithm and its rounds, the words in order, the joiner
 * and the case.
 *
 * @param recipe - The transform that matched.
 * @returns {string} The line.
 */
function recipeLine(recipe: DigestRecipe): string {
  const rounds = recipe.rounds > 1 ? `, ${recipe.rounds} rounds chained as ${recipe.chain}` : "";
  const words =
    recipe.words.length > 1
      ? `words ${quotedList(recipe.words)} joined by ${quoted(recipe.joiner)}`
      : `word ${quoted(recipe.words[0]!)}`;
  const parameters = Object.entries(recipe.parameters ?? {})
    .map(([name, value]) => ` ${name} ${value}`)
    .join("");
  return `${recipe.algorithm}${parameters} of the ${words}, case ${recipe.case}${rounds}`;
}

/**
 * Describes what a search covered, for an answer without a match.
 *
 * @param scope - What it covered.
 * @returns {string} The line.
 */
function scopeLine(scope: SearchScope): string {
  const sizes =
    scope.minWords === scope.maxWords
      ? `${scope.minWords}`
      : `${scope.minWords} to ${scope.maxWords}`;
  const skipped =
    scope.chains.includes("bytes") && scope.textOnly.length > 0
      ? `, no bytes chain for ${scope.textOnly.join(", ")}`
      : "";
  const rounds =
    scope.rounds > 1
      ? `up to ${scope.rounds} rounds chained as ${scope.chains.join(", ")}${skipped}`
      : "1 round";
  return [
    `Covered ${sizes} of the words ${quotedList(scope.words)}`,
    `joiners ${quotedList(scope.joiners)}`,
    `cases ${scope.cases.join(", ")}`,
    `algorithms ${scope.algorithms.join(", ")}`,
    `${rounds}.`,
  ].join("; ");
}

/**
 * Counts hashes the way a verdict says it.
 *
 * @param total - The hashes.
 * @returns {string} `1 hash` or `<n> hashes`.
 */
function hashCount(total: number): string {
  return total === 1 ? "1 hash" : `${total} hashes`;
}

/**
 * Writes a search's verdict the way the CLI and the tool print it: a heading, then on a match the
 * recipe and the text that was hashed.
 *
 * @param found - The search's result.
 * @returns {{ heading: string[]; lines: string[] }} The heading, then the lines of the match.
 */
export function searchText(found: DigestSearch | DigestSearchBatch): {
  heading: string[];
  lines: string[];
} {
  if ("items" in found) return batchText(found);
  const hashes = hashCount(found.total);
  const count = `${found.tried} of ${hashes}`;
  if (found.recipe !== undefined) {
    return {
      heading: [`MATCH after ${count}`],
      lines: [recipeLine(found.recipe), `input ${quoted(found.recipe.input)}`],
    };
  }
  const verdict = found.stopped
    ? `STOPPED at the limit after ${count}, no match so far`
    : `NO MATCH in ${hashes}`;
  return { heading: [verdict, scopeLine(found.scope)], lines: [] };
}

/**
 * Writes the verdict for a list: how many got a recipe, then one block per digest.
 *
 * @param found - The search's result.
 * @returns {{ heading: string[]; lines: string[] }} The heading, then one block per digest.
 */
function batchText(found: DigestSearchBatch): { heading: string[]; lines: string[] } {
  const hashes = hashCount(found.total);
  const count = `${found.tried} of ${hashes}`;
  const digests = found.items.length === 1 ? "1 digest" : `${found.items.length} digests`;
  const matched = found.items.filter((item) => item.recipe !== undefined).length;
  const stop = found.stopped ? ", then STOPPED at the limit" : "";
  let verdict = `MATCH for ${matched} of ${digests} after ${count}${stop}`;
  if (matched === 0) {
    verdict = found.stopped
      ? `STOPPED at the limit after ${count}, no match so far`
      : `NO MATCH for ${digests} in ${hashes}`;
  }
  const missing = found.items.filter((item) => item.recipe === undefined);
  const covered = [...new Set(missing.map((item) => scopeLine(item.scope)))];
  const none = found.stopped ? "no match so far" : "NO MATCH";
  const lines = found.items.flatMap((item) =>
    item.recipe === undefined
      ? [`${item.digest} ${none}`]
      : [`${item.digest} MATCH`, recipeLine(item.recipe), `input ${quoted(item.recipe.input)}`],
  );
  return { heading: [verdict, ...covered], lines };
}
