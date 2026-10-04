import { defineCommand } from "citty";
import { searchDigest, searchText, type SearchCase, type SearchChain } from "../core/search.ts";
import { assertExpected } from "../core/verify.ts";
import { InvalidOptionError, MissingOptionError } from "../index.ts";
import { parseEncoding } from "./shared.ts";

/** Most hashes a search runs unless `--limit` says otherwise: a few minutes of SHA-256. */
const DEFAULT_LIMIT = 100_000_000;

/**
 * Reads a whole number flag.
 *
 * @param flag - The flag name, for the error.
 * @param value - The flag as given.
 * @returns {number | undefined} The number, or nothing when the flag was left out.
 */
function readCount(flag: string, value: string | undefined): number | undefined {
  if (value === undefined) return undefined;
  if (!/^\d{1,15}$/.test(value))
    throw new InvalidOptionError(flag, value, "must be a whole number");
  return Number(value);
}

/**
 * Reads a comma-separated flag.
 *
 * @param value - The flag as given.
 * @returns {string[] | undefined} The values, or nothing when the flag was left out.
 */
function readList(value: string | undefined): string[] | undefined {
  return value?.split(",").map((entry) => entry.trim());
}

/**
 * Reads `--joiners`, a JSON array of strings, since a joiner may be a comma or a line feed.
 *
 * @param value - The flag as given.
 * @returns {string[] | undefined} The joiners, or nothing when the flag was left out.
 */
function readJoiners(value: string | undefined): string[] | undefined {
  if (value === undefined) return undefined;
  let parsed: unknown;
  try {
    parsed = JSON.parse(value);
  } catch {
    parsed = undefined;
  }
  if (!Array.isArray(parsed) || !parsed.every((entry) => typeof entry === "string")) {
    throw new InvalidOptionError(
      "joiners",
      value,
      'must be a JSON array of strings, such as \'["", "-"]\'',
    );
  }
  return parsed as string[];
}

/** Prints the total, then the running count over itself on a terminal; a pipe gets the total. */
class Progress {
  drawn = false;

  /**
   * Hears the search's count.
   *
   * @param tried - Hashes computed so far.
   * @param total - Hashes in the scope.
   */
  readonly show = (tried: number, total: number): void => {
    if (tried === 0) {
      process.stderr.write(`Searching ${total === 1 ? "1 hash" : `${total} hashes`}\n`);
    } else if (process.stderr.isTTY) {
      process.stderr.write(`\r${tried} of ${total} hashes`);
      this.drawn = true;
    }
  };

  /** Clears the running count before the verdict. */
  clear(): void {
    if (this.drawn) process.stderr.write("\r\u001B[2K");
  }
}

export default defineCommand({
  meta: {
    name: "search",
    description:
      "Find which words, in which order, joined and cased how, hashed with which algorithm how many times, give a digest",
  },
  args: {
    digest: {
      type: "positional",
      description: "The digest, in hex unless --encoding says otherwise; the words follow it",
      required: true,
    },
    encoding: {
      type: "string",
      description: "Encoding of the digest: hex, base64 or base64url",
      alias: "e",
      default: "hex",
    },
    "min-words": { type: "string", description: "Fewest words in a combination (default 1)" },
    "max-words": { type: "string", description: "Most words in a combination (default all)" },
    joiners: {
      type: "string",
      description: 'What goes between two words, a JSON array (default ["", " ", ",", "\\n"])',
    },
    cases: {
      type: "string",
      description: "Comma-separated cases to try: as-is, lower, upper, title (default all)",
    },
    algorithms: {
      type: "string",
      description: "Comma-separated algorithms to try (default every digest as long as the target)",
    },
    rounds: {
      type: "string",
      description: "Deepest repetition: 2 also hashes each digest once more (default 1)",
    },
    chains: {
      type: "string",
      description:
        "Comma-separated, what each next round hashes: bytes, hex, hex-upper (default all)",
    },
    limit: {
      type: "string",
      description: `Most hashes to compute before stopping (default ${DEFAULT_LIMIT})`,
    },
  },
  run({ args }) {
    const encoding = parseEncoding(args.encoding);
    if (encoding === "binary") {
      throw new InvalidOptionError("encoding", encoding, "use hex, base64 or base64url");
    }
    const target = assertExpected(args.digest, encoding, "digest");
    const words = args._.slice(1).map(String);
    if (words.length === 0) throw new MissingOptionError("words (after the digest)");
    const progress = new Progress();
    const found = searchDigest(target, {
      words,
      minWords: readCount("min-words", args["min-words"]),
      maxWords: readCount("max-words", args["max-words"]),
      joiners: readJoiners(args.joiners),
      cases: readList(args.cases) as SearchCase[] | undefined,
      algorithms: readList(args.algorithms),
      rounds: readCount("rounds", args.rounds),
      chains: readList(args.chains) as SearchChain[] | undefined,
      limit: readCount("limit", args.limit) ?? DEFAULT_LIMIT,
      onProgress: progress.show,
    });
    progress.clear();
    const { heading, lines } = searchText(found);
    for (const line of heading) process.stderr.write(`${line}\n`);
    for (const line of lines) process.stdout.write(`${line}\n`);
    if (lines.length === 0) process.exitCode = 1;
  },
});
