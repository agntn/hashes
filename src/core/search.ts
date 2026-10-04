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
import type { Hash } from "./hash.ts";

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
 * @returns {number[]} At index k, the cased combinations of k words, before ordering and joining.
 */
function casedCombinations(
  words: readonly string[],
  cases: readonly SearchCase[],
  maxWords: number,
): number[] {
  const bySize: Map<string, number>[] = [new Map([[partition(cases.map(() => "")), 1]])];
  for (const word of words) {
    const split = partition(cases.map((form) => caseWord(word, form)));
    for (let size = Math.min(bySize.length, maxWords) - 1; size >= 0; size--) {
      const next = (bySize[size + 1] ??= new Map());
      for (const [key, count] of bySize[size]!) {
        const joined = meet(key, split);
        next.set(joined, (next.get(joined) ?? 0) + count);
      }
    }
  }
  return bySize.map((splits) =>
    [...splits].reduce((sum, [key, count]) => sum + count * new Set(key.split(",")).size, 0),
  );
}

/**
 * Counts the hashes a scope holds.
 *
 * @param scope - What the search covers.
 * @returns {number} Every hash it would compute without a match.
 */
function scopeSize(scope: SearchScope): number {
  const combinations = casedCombinations(scope.words, scope.cases, scope.maxWords);
  let texts = 0;
  let orderings = 1;
  for (let size = 1; size <= scope.maxWords; size++) {
    orderings *= size;
    if (size < scope.minWords) continue;
    const joiners = size === 1 ? 1 : scope.joiners.length;
    texts += (combinations[size] ?? 0) * orderings * joiners;
  }
  const chained = scope.rounds > 1 ? scope.chains.length * (scope.rounds - 1) : 0;
  return texts * scope.algorithms.length * (1 + chained);
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
 * Lists every text a scope makes, the smallest combinations first.
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

/**
 * Resolves the algorithms to try: the ones named, or every fixed-length digest of the target's
 * length. A KDF draws or takes a salt and is no transform of the words alone, so it is refused.
 *
 * @param named - The algorithms as given, if any.
 * @param length - The target's length in bytes.
 * @returns {Hash[]} The algorithms.
 */
function searchAlgorithms(named: readonly string[] | undefined, length: number): Hash[] {
  if (named === undefined) {
    const fitting = algorithms()
      .map((name) => create(name))
      .filter((hash) => isFixed(hash) && hash.info().digestLength === length);
    if (fitting.length === 0) {
      const size = length === 1 ? "1 byte" : `${length} bytes`;
      throw new InvalidOptionError("digest", size, "no registered digest is that long");
    }
    return fitting;
  }
  const resolved = distinct("algorithms", named).map((name) => resolveAlgorithm(name));
  for (const hash of resolved) {
    const size = hash.info().digestLength;
    if (!isFixed(hash)) {
      throw new InvalidOptionError("algorithms", hash.name(), "is no fixed-length digest");
    }
    if (size !== length) {
      throw new InvalidOptionError(
        "algorithms",
        hash.name(),
        `makes ${size} bytes and the digest is ${length}`,
      );
    }
  }
  return [...new Map(resolved.map((hash) => [hash.name(), hash])).values()];
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

/**
 * Checks the options and fills in the defaults.
 *
 * @param target - The digest.
 * @param options - The caller's options.
 * @returns {{ scope: SearchScope; hashes: Hash[] }} The scope and the algorithms in it.
 */
function searchScope(
  target: Uint8Array,
  options: SearchDigestOptions,
): { scope: SearchScope; hashes: Hash[] } {
  if (target.length === 0)
    throw new InvalidOptionError("digest", "(empty)", "needs at least one byte");
  const words = wordList(options.words);
  const maxWords = wholeNumber("maxWords", options.maxWords ?? words.length, 1, words.length);
  const minWords = wholeNumber("minWords", options.minWords ?? 1, 1, maxWords);
  const hashes = searchAlgorithms(options.algorithms, target.length);
  const scope: SearchScope = {
    words,
    minWords,
    maxWords,
    joiners: distinct("joiners", options.joiners ?? SEARCH_JOINERS),
    cases: distinct("cases", options.cases ?? SEARCH_CASES, SEARCH_CASES),
    algorithms: hashes.map((hash) => hash.name()),
    rounds: wholeNumber("rounds", options.rounds ?? 1, 1, Number.MAX_SAFE_INTEGER),
    chains: distinct("chains", options.chains ?? SEARCH_CHAINS, SEARCH_CHAINS),
  };
  return { scope, hashes };
}

/**
 * Hashes a digest again as a chain says.
 *
 * @param hash - The algorithm.
 * @param digest - The previous round's digest.
 * @param chain - What to hash of it.
 * @returns {Uint8Array} The next round's digest.
 */
function nextRound(hash: Hash, digest: Uint8Array, chain: SearchChain): Uint8Array {
  if (chain === "bytes") return digestOf(hash, digest);
  const hex = digest.toHex();
  return digestOf(hash, toBytes(chain === "hex" ? hex : hex.toUpperCase()));
}

/**
 * Hashes bytes to raw digest bytes.
 *
 * @param hash - The algorithm.
 * @param bytes - What to hash.
 * @returns {Uint8Array} The digest.
 */
function digestOf(hash: Hash, bytes: Uint8Array): Uint8Array {
  const { digest } = hash.hash(bytes, { encoding: "binary" });
  if (!(digest instanceof Uint8Array)) throw new TypeError(`${hash.name()} returned no bytes`);
  return digest;
}

/** Why a candidate's hashes ended: a match, the limit, or none of them fit. */
type Outcome = DigestRecipe | "limit" | undefined;

/** One search: its scope, the running count against the limit, and the progress it reports. */
class Search {
  readonly #target: Uint8Array;
  readonly #scope: SearchScope;
  readonly #total: number;
  readonly #limit: number;
  readonly #onProgress: SearchDigestOptions["onProgress"];
  #tried = 0;

  constructor(target: Uint8Array, scope: SearchScope, options: SearchDigestOptions) {
    this.#target = target;
    this.#scope = scope;
    this.#total = scopeSize(scope);
    this.#limit = options.limit ?? Infinity;
    this.#onProgress = options.onProgress;
    this.#onProgress?.(0, this.#total);
  }

  /**
   * Tries every candidate with every algorithm until one matches or the limit ends it.
   *
   * @param hashes - The algorithms.
   * @returns {DigestSearch} The result.
   */
  run(hashes: readonly Hash[]): DigestSearch {
    const ended = { total: this.#total, scope: this.#scope };
    for (const candidate of candidatesOf(this.#scope)) {
      for (const hash of hashes) {
        const outcome = this.#candidate(candidate, hash);
        if (outcome === "limit") return { ...ended, tried: this.#tried, stopped: true };
        if (outcome !== undefined) {
          return { ...ended, tried: this.#tried, recipe: outcome, stopped: false };
        }
      }
    }
    return { ...ended, tried: this.#tried, stopped: false };
  }

  /**
   * Counts one hash about to be computed.
   *
   * @returns {boolean} Whether the limit still allows it.
   */
  #next(): boolean {
    if (this.#tried >= this.#limit) return false;
    this.#tried++;
    if (this.#tried % PROGRESS_INTERVAL === 0) this.#onProgress?.(this.#tried, this.#total);
    return true;
  }

  /**
   * Hashes one text with one algorithm, then again round after round in each chain.
   *
   * @param candidate - The text and its recipe.
   * @param hash - The algorithm.
   * @returns {Outcome} The recipe on a match, `limit` when the limit ended it.
   */
  #candidate(candidate: Candidate, hash: Hash): Outcome {
    if (!this.#next()) return "limit";
    const first = digestOf(hash, toBytes(candidate.input));
    const recipe = { ...candidate, algorithm: hash.name() };
    if (sameBytes(first, this.#target)) return { ...recipe, rounds: 1 };
    if (this.#scope.rounds === 1) return undefined;
    for (const chain of this.#scope.chains) {
      const outcome = this.#chain(first, hash, chain);
      if (outcome !== undefined) return outcome === "limit" ? outcome : { ...recipe, ...outcome };
    }
    return undefined;
  }

  /**
   * Hashes a digest again round after round in one chain. A chain the algorithm cannot take,
   * such as raw bytes for NTLM, which hashes UTF-8 text only, ends there without a match.
   *
   * @param first - The first round's digest.
   * @param hash - The algorithm.
   * @param chain - What each next round hashes.
   * @returns {{ rounds: number; chain: SearchChain } | "limit" | undefined} The round that matched.
   */
  #chain(
    first: Uint8Array,
    hash: Hash,
    chain: SearchChain,
  ): { rounds: number; chain: SearchChain } | "limit" | undefined {
    let digest = first;
    for (let rounds = 2; rounds <= this.#scope.rounds; rounds++) {
      if (!this.#next()) return "limit";
      try {
        digest = nextRound(hash, digest, chain);
      } catch (error) {
        if (error instanceof HashError) return undefined;
        throw error;
      }
      if (sameBytes(digest, this.#target)) return { rounds, chain };
    }
    return undefined;
  }
}

/**
 * Tries the words in every subset and order, joined, cased and hashed as UTF-8, smallest
 * combinations first, until one gives the digest or the limit ends the search.
 *
 * @param target - The digest, as bytes.
 * @param options - The words and what to try with them.
 * @returns {DigestSearch} How many hashes the scope held and were tried, and the recipe on a match.
 */
export function searchDigest(target: Uint8Array, options: SearchDigestOptions): DigestSearch {
  if (options.limit !== undefined) wholeNumber("limit", options.limit, 1, Number.MAX_SAFE_INTEGER);
  const { scope, hashes } = searchScope(target, options);
  return new Search(target, scope, options).run(hashes);
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
  return `${recipe.algorithm} of the ${words}, case ${recipe.case}${rounds}`;
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
  const rounds =
    scope.rounds > 1
      ? `up to ${scope.rounds} rounds chained as ${scope.chains.join(", ")}`
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
 * Writes a search's verdict the way the CLI and the tool print it: a heading, then on a match the
 * recipe and the text that was hashed.
 *
 * @param found - The search's result.
 * @returns {{ heading: string[]; lines: string[] }} The heading, then the lines of the match.
 */
export function searchText(found: DigestSearch): { heading: string[]; lines: string[] } {
  const hashes = found.total === 1 ? "1 hash" : `${found.total} hashes`;
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
