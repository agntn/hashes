/**
 * The commands only the CLI gets: bytes from stdin, a digest alone on stdout, and a search that
 * runs past the tool's cap. Each takes the place of the tool command with its name.
 */

import { readFileSync } from "node:fs";
import {
  defineTool,
  Type,
  type TObject,
  type TOptional,
  type TProperties,
  type TString,
  type ToolResult,
} from "@agntn/tools";
import { INPUT_ENCODINGS, TEXT_ENCODINGS } from "../packages/shared/tool-contract.ts";
import { ENCODING_OPTION, decodeInput, parameterText, type InputEncoding } from "./core/digest.ts";
import { shown } from "./core/errors.ts";
import { identifyDigest, identityText } from "./core/identify.ts";
import { searchDigest, searchText, type SearchCase, type SearchChain } from "./core/search.ts";
import { assertDrawnOptions, assertExpected } from "./core/verify.ts";
import {
  InvalidOptionError,
  builtinAlgorithms,
  checkedParameters,
  create,
  digestMatches,
  parameterOptions,
  resolveAlgorithm,
  type Hash,
  type HashInput,
  type HashOptions,
  type HashResult,
  type ParameterValue,
} from "./index.ts";

/** Most hashes a search runs unless `--limit` says otherwise: a few minutes of SHA-256. */
const DEFAULT_LIMIT = 100_000_000;

/**
 * An object schema that refuses keys it does not declare.
 *
 * @param properties - The declared properties.
 * @returns {TObject} The closed object schema.
 */
function closed<T extends TProperties>(properties: T): TObject<T> {
  return Type.Object(properties, { additionalProperties: false });
}

/**
 * Names the algorithms that take a flag, or the ones that don't when those are fewer.
 *
 * @param algorithms - The algorithms that declare the option.
 * @returns {string} The shorter list.
 */
function takenBy(algorithms: readonly string[]): string {
  const others = builtinAlgorithms.filter((name) => !algorithms.includes(name));
  if (others.length === 0) return "all";
  return others.length < algorithms.length ? `all but ${others.join(", ")}` : algorithms.join(", ");
}

/**
 * One flag per option the built-in algorithms take besides encoding and key, such as `--salt`,
 * `--seed`, `--n` or `--iterations`, each naming the algorithms that declare it.
 *
 * @returns {Record<string, TOptional<TString>>} The flags by option name.
 */
function builtinParameters(): Record<string, TOptional<TString>> {
  const flags = new Map<string, { description: string; algorithms: string[] }>();
  for (const name of builtinAlgorithms) {
    for (const option of parameterOptions(create(name))) {
      const flag = flags.get(option.name) ?? { description: option.description, algorithms: [] };
      flag.algorithms.push(name);
      flags.set(option.name, flag);
    }
  }
  return Object.fromEntries(
    [...flags].map(([name, flag]) => [
      name,
      Type.Optional(
        Type.String({ description: `${flag.description} (${takenBy(flag.algorithms)})` }),
      ),
    ]),
  );
}

const parameters = builtinParameters();

/**
 * Reads the parameter flags that were given and checks them against the algorithm, so a flag
 * the algorithm does not take is an error instead of a digest computed without it.
 *
 * @param algorithm - The resolved algorithm.
 * @param args - The parsed arguments.
 * @returns {Record<string, ParameterValue>} The options to hash with.
 */
function readParameters(
  algorithm: Hash,
  args: Readonly<Record<string, unknown>>,
): Record<string, ParameterValue> {
  const given = Object.fromEntries(
    Object.keys(parameters)
      .filter((name) => args[name] !== undefined)
      .map((name) => [name, args[name]] as const),
  );
  return checkedParameters(algorithm, given);
}

/**
 * Reads the input argument: `-` means stdin, anything else is the input itself. In utf8 it is
 * hashed as given, stdin byte for byte; in hex or base64 it is decoded to the bytes it spells.
 *
 * @param value - The argument as given.
 * @param encoding - How to read it.
 * @returns {HashInput} Text, or bytes.
 */
function readInput(value: string, encoding: InputEncoding = "utf8"): HashInput {
  const stdin = value === "-" ? new Uint8Array(readFileSync(0)) : undefined;
  if (encoding === "utf8") return stdin ?? value;
  const text = stdin === undefined ? value : new TextDecoder().decode(stdin);
  return decodeInput(text, encoding);
}

/**
 * Prints a digest the way `sha256sum` users expect: text with a newline, bytes as they are. A
 * salted digest cannot be reproduced without its salt and cost, so those go to stderr.
 *
 * @param result - The computed hash.
 * @returns {ToolResult<null>} The digest as text, or nothing once the bytes are out.
 */
function printDigest(result: HashResult): ToolResult<null> {
  if ("salt" in result.options) process.stderr.write(`${parameterText(result.options)}\n`);
  if (typeof result.digest === "string") {
    return { content: [{ type: "text", text: result.digest }], details: null };
  }
  process.stdout.write(result.digest);
  return { content: [], details: null };
}

/**
 * The text of a report that found something, or an empty report with exit code 1, like `grep`.
 *
 * @param lines - What was found, one line each.
 * @param details - What `--json` prints.
 * @returns {ToolResult<T>} The report.
 */
function found<T>(lines: readonly string[], details: T): ToolResult<T> {
  if (lines.length === 0) {
    process.exitCode = 1;
    return { content: [], details };
  }
  return { content: [{ type: "text", text: lines.join("\n") }], details };
}

const algorithm = Type.String({
  minLength: 1,
  description: "Algorithm name (sha256, blake3, md5, ...)",
});
const input = Type.String({ description: "Text to hash, or - for stdin, read byte for byte" });
const inputEncoding = Type.Optional(
  Type.Enum(INPUT_ENCODINGS, {
    description:
      "How to read the input: utf8, or hex and base64 for the bytes they spell (a public key, a raw transaction)",
  }),
);

export const hashCommand = defineTool({
  name: "hashes_hash",
  title: "Hash",
  description: "Hash input with an algorithm",
  effect: "read",
  input: closed({
    algorithm,
    input,
    inputEncoding,
    encoding: Type.Optional(
      Type.Enum([...TEXT_ENCODINGS, "binary"], { description: ENCODING_OPTION.description }),
    ),
    ...parameters,
  }),
  cli: {
    command: "hash",
    positional: ["algorithm", "input"],
    short: { encoding: "e" },
    json: false,
  },
  execute: (params) => {
    const hash = resolveAlgorithm(params.algorithm);
    return printDigest(
      hash.hash(readInput(params.input, params.inputEncoding), {
        encoding: params.encoding ?? "hex",
        ...readParameters(hash, params),
      } as HashOptions),
    );
  },
});

export const hmacCommand = defineTool({
  name: "hashes_hmac",
  title: "HMAC",
  description: "Compute HMAC with an algorithm",
  effect: "read",
  input: closed({
    algorithm: Type.String({
      minLength: 1,
      description: "Algorithm name (sha256, sha512, blake2b, ...)",
    }),
    input: Type.String({ description: "Text to HMAC, or - for stdin, read byte for byte" }),
    key: Type.String({ description: "HMAC key" }),
    inputEncoding,
    keyEncoding: Type.Optional(
      Type.Enum(INPUT_ENCODINGS, {
        description:
          "How to read the key: utf8, or hex and base64 for a binary key (a BIP32 chain code)",
      }),
    ),
    encoding: Type.Optional(
      Type.Enum([...TEXT_ENCODINGS, "binary"], { description: ENCODING_OPTION.description }),
    ),
  }),
  cli: {
    command: "hmac",
    positional: ["algorithm", "input", "key"],
    short: { encoding: "e" },
    json: false,
  },
  execute: (params) => {
    const hash = resolveAlgorithm(params.algorithm);
    if (!hash.info().hmac) {
      throw new InvalidOptionError("algorithm", hash.name(), "has no HMAC mode");
    }
    const key = decodeInput(params.key, params.keyEncoding ?? "utf8", "key");
    return printDigest(
      hash.hash(readInput(params.input, params.inputEncoding), {
        encoding: params.encoding ?? "hex",
        key,
      }),
    );
  },
});

export const verifyCommand = defineTool({
  name: "hashes_verify",
  title: "Verify",
  description: "Verify input against an expected hash, exit 1 on a mismatch",
  effect: "read",
  input: closed({
    algorithm,
    input,
    expected: Type.String({ minLength: 1, description: "Expected hash digest" }),
    inputEncoding,
    encoding: Type.Optional(
      Type.Enum(TEXT_ENCODINGS, {
        description: "Encoding of the expected digest: hex, base64, base64url",
      }),
    ),
    ...parameters,
  }),
  cli: { positional: ["algorithm", "input", "expected"], short: { encoding: "e" } },
  execute: (params) => {
    const hash = resolveAlgorithm(params.algorithm);
    const encoding = params.encoding ?? "hex";
    assertExpected(params.expected, encoding);
    const options = readParameters(hash, params);
    assertDrawnOptions(hash.info(), options);
    const result = hash.hash(readInput(params.input, params.inputEncoding), {
      encoding,
      ...options,
    } as HashOptions);
    const digest = String(result.digest);
    const match = digestMatches(result, params.expected);
    if (!match) process.exitCode = 1;
    const text = match
      ? `MATCH ${hash.name()} ${digest}`
      : `MISMATCH ${hash.name()}\n  expected ${shown(params.expected.trim())}\n  actual   ${digest}`;
    return {
      content: [{ type: "text", text }],
      details: { match, algorithm: hash.name(), digest },
    };
  },
});

export const identifyCommand = defineTool({
  name: "hashes_identify",
  title: "Identify",
  description: "Guess which algorithms a hash may come from, by its prefix or its length",
  effect: "read",
  input: closed({
    digest: Type.String({
      minLength: 1,
      description: "The hash: hex, base64, or a string such as $2b$... (quote it in the shell)",
    }),
  }),
  cli: { command: "identify", positional: ["digest"] },
  execute: ({ digest }) => {
    const identity = identifyDigest(digest);
    const { heading, lines } = identityText(identity);
    process.stderr.write(`${heading}\n`);
    return found(lines, identity);
  },
});

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

/**
 * Reads a comma-separated flag.
 *
 * @param value - The flag as given.
 * @returns {string[] | undefined} The values, or nothing when the flag was left out.
 */
function readList(value: string | undefined): string[] | undefined {
  return value?.split(",").map((entry) => entry.trim());
}

const count = (description: string) => Type.Optional(Type.Integer({ minimum: 0, description }));

export const searchCommand = defineTool({
  name: "hashes_search",
  title: "Search",
  description:
    "Find which words, in which order, joined and cased how, hashed with which algorithm how many times, give a digest",
  effect: "read",
  input: closed({
    digest: Type.String({
      minLength: 1,
      description: "The digest, in hex unless --encoding says otherwise; the words follow it",
    }),
    words: Type.String({
      minLength: 1,
      description: "The words to combine, one argument each; a quoted space splits them too",
    }),
    encoding: Type.Optional(
      Type.Enum(TEXT_ENCODINGS, { description: "Encoding of the digest: hex, base64, base64url" }),
    ),
    minWords: count("Fewest words in a combination (default 1)"),
    maxWords: count("Most words in a combination (default all)"),
    joiners: Type.Optional(
      Type.Array(Type.String(), {
        minItems: 1,
        description: 'What goes between two words, a JSON array (default ["", " ", ",", "\\n"])',
      }),
    ),
    cases: Type.Optional(
      Type.String({
        description: "Comma-separated cases to try: as-is, lower, upper, title (default all)",
      }),
    ),
    algorithms: Type.Optional(
      Type.String({
        description:
          "Comma-separated algorithms to try (default every digest as long as the target)",
      }),
    ),
    rounds: count("Deepest repetition: 2 also hashes each digest once more (default 1)"),
    chains: Type.Optional(
      Type.String({
        description:
          "Comma-separated, what each next round hashes: bytes, hex, hex-upper (default all)",
      }),
    ),
    limit: count(`Most hashes to compute before stopping (default ${DEFAULT_LIMIT})`),
  }),
  cli: { command: "search", positional: ["digest"], rest: "words", short: { encoding: "e" } },
  execute: (params) => {
    const target = assertExpected(params.digest, params.encoding ?? "hex", "digest");
    const progress = new Progress();
    const result = searchDigest(target, {
      words: params.words.split(" ").filter((word) => word !== ""),
      minWords: params.minWords,
      maxWords: params.maxWords,
      joiners: params.joiners,
      cases: readList(params.cases) as SearchCase[] | undefined,
      algorithms: readList(params.algorithms),
      rounds: params.rounds,
      chains: readList(params.chains) as SearchChain[] | undefined,
      limit: params.limit ?? DEFAULT_LIMIT,
      onProgress: progress.show,
    });
    progress.clear();
    const { heading, lines } = searchText(result);
    for (const line of heading) process.stderr.write(`${line}\n`);
    return found(lines, result);
  },
});

/** Every command of the CLI's own, each in the place of the tool command it shares a name with. */
export const cliCommands = [
  hashCommand,
  hmacCommand,
  verifyCommand,
  identifyCommand,
  searchCommand,
];
