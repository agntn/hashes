/**
 * The commands only the CLI gets: bytes from stdin, a digest alone on stdout, and a search that
 * runs past the tool's cap. Each takes the place of the tool command with its name.
 */

import { readFileSync, writeFileSync } from "node:fs";
import {
  defineTool,
  Type,
  type TObject,
  type TOptional,
  type TProperties,
  type TString,
  type ToolResult,
} from "@agntn/tools";
import { INPUT_ENCODINGS, TEXT_ENCODINGS } from "../extensions/shared/tool-contract.ts";
import { ENCODING_OPTION, decodeInput, parameterText, type InputEncoding } from "./core/digest.ts";
import { HashError, quoted, shown } from "./core/errors.ts";
import { HMAC_ONE_ROUND } from "./core/fixed-hash.ts";
import { identifyDigest, identityText, type DigestIdentity } from "./core/identify.ts";
import {
  searchDigest,
  searchText,
  type SearchCase,
  type SearchChain,
  type SearchDigestOptions,
} from "./core/search.ts";
import { assertDrawnOptions, assertExpected } from "./core/verify.ts";
import { plainLine } from "./core/manifest.ts";
import {
  checkManifest,
  createManifest,
  hashFile,
  type CreatedManifest,
  type ManifestCheck,
  type ManifestResult,
} from "./files.ts";
import {
  InvalidOptionError,
  builtinAlgorithms,
  checkedParameters,
  create,
  digestMatches,
  oneRoundOptions,
  parameterOptions,
  resolveAlgorithm,
  type Hash,
  type HashInput,
  type HashOption,
  type HashOptions,
  type HashResult,
  type ParameterValue,
} from "./index.ts";
import {
  counted,
  digestDetails,
  digestLines,
  lengthMismatch,
  settled,
  verifyListText,
  type BatchError,
  type DigestDetails,
  type TextEncoding,
  type VerifyDetails,
} from "./tool-operations.ts";

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
 * Describes a flag by each meaning it has. `--bits` is one thing to HAVAL and another to xxHash.
 *
 * @param meanings - Each description, with the algorithms that declare the option with it.
 * @returns {string} The flag's help text.
 */
function flagDescription(meanings: readonly (readonly [string, readonly string[]])[]): string {
  const [only] = meanings;
  if (meanings.length === 1 && only) return `${only[0]} (${takenBy(only[1])})`;
  return meanings.map(([text, names]) => `${text} (${names.join(", ")})`).join("; ");
}

/**
 * One flag per option the built-in algorithms take besides encoding and key, such as `--salt`,
 * `--seed`, `--n` or `--iterations`, each naming the algorithms that declare it.
 *
 * @param names - The algorithms whose options become flags.
 * @param optionsOf - Which of an algorithm's options the command takes: `oneRoundOptions` for HMAC.
 * @returns {Record<string, TOptional<TString>>} The flags by option name.
 */
function builtinParameters(
  names: readonly string[],
  optionsOf: (algorithm: Hash) => HashOption[] = parameterOptions,
): Record<string, TOptional<TString>> {
  const flags = new Map<string, Map<string, string[]>>();
  for (const name of names) {
    for (const option of optionsOf(create(name))) {
      const meanings = flags.get(option.name) ?? new Map<string, string[]>();
      meanings.set(option.description, [...(meanings.get(option.description) ?? []), name]);
      flags.set(option.name, meanings);
    }
  }
  return Object.fromEntries(
    [...flags].map(([name, meanings]) => [
      name,
      Type.Optional(Type.String({ description: flagDescription([...meanings]) })),
    ]),
  );
}

const parameters = builtinParameters(builtinAlgorithms);
const hmacParameters = builtinParameters(
  builtinAlgorithms.filter((name) => create(name).info().hmac),
  oneRoundOptions,
);

/**
 * Reads the parameter flags that were given and checks them against the algorithm, so a flag
 * the algorithm does not take is an error instead of a digest computed without it.
 *
 * @param algorithm - The resolved algorithm.
 * @param args - The parsed arguments.
 * @param flags - The parameter flags the command takes.
 * @param oneRound - Why the command runs one round, for HMAC.
 * @returns {Record<string, ParameterValue>} The options to hash with.
 */
function readParameters(
  algorithm: Hash,
  args: Readonly<Record<string, unknown>>,
  flags: Readonly<Record<string, unknown>> = parameters,
  oneRound?: string,
): Record<string, ParameterValue> {
  const given = Object.fromEntries(
    Object.keys(flags)
      .filter((name) => args[name] !== undefined)
      .map((name) => [name, args[name]] as const),
  );
  return checkedParameters(algorithm, given, oneRound);
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
 * Reads every input of a list. `-` takes stdin, which runs dry after one read, so only one may.
 *
 * @param texts - The inputs as given.
 * @param encoding - How to read them.
 * @returns {Array<HashInput | BatchError>} What to hash, or why an input can't be read.
 */
function readInputs(
  texts: readonly string[],
  encoding: InputEncoding | undefined,
): Array<HashInput | BatchError> {
  if (texts.filter((text) => text === "-").length > 1) {
    throw new InvalidOptionError("input", "-", "stdin reads once, so only one input can be -");
  }
  return texts.map((text) => settled(() => readInput(text, encoding)));
}

/**
 * Tells a refused input from a result.
 *
 * @param value - An entry of a list.
 * @returns {value is BatchError} Whether it holds the reason it has no result.
 */
function isBatchError(value: unknown): value is BatchError {
  return typeof value === "object" && value !== null && "error" in value;
}

/**
 * Refuses `-e binary` for a list, since raw digests would run together with nothing between.
 *
 * @param encoding - The digest encoding asked for.
 * @returns {TextEncoding} The encoding, now known to be text.
 */
function listEncoding(encoding: string): TextEncoding {
  const text = TEXT_ENCODINGS.find((name) => name === encoding);
  if (text !== undefined) return text;
  throw new InvalidOptionError(
    "encoding",
    encoding,
    "writes one digest alone; hash several inputs in hex or base64",
  );
}

/**
 * Prints `sha256sum` lines on stdout and their heading on stderr, exit 1 if an input fails.
 *
 * @param texts - The inputs as given.
 * @param encoding - How to read them.
 * @param digest - Hashes one input.
 * @returns {ToolResult<{ items: Array<DigestDetails | BatchError> }>} The lines.
 */
function printDigests(
  texts: readonly string[],
  encoding: InputEncoding | undefined,
  digest: (input: HashInput) => DigestDetails,
): ToolResult<{ items: Array<DigestDetails | BatchError> }> {
  const items = readInputs(texts, encoding).map((input) =>
    isBatchError(input) ? input : settled(() => digest(input)),
  );
  const { about, lines } = digestLines(items, texts);
  process.stderr.write(`${counted(items.length, "input")}, ${about ?? "none hashed"}\n`);
  if (items.some(isBatchError)) process.exitCode = 1;
  return { content: [{ type: "text", text: lines.join("\n") }], details: { items } };
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
const inputs = Type.Array(Type.String(), {
  minItems: 1,
  description: "Text to hash, or - for stdin, read byte for byte; several get a line each",
});
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
    input: inputs,
    inputEncoding,
    file: Type.Optional(
      Type.Boolean({
        description:
          "Read each input as a file path and hash its bytes as they are; without it a path is just text",
      }),
    ),
    encoding: Type.Optional(
      Type.Enum([...TEXT_ENCODINGS, "binary"], { description: ENCODING_OPTION.description }),
    ),
    ...parameters,
  }),
  cli: {
    command: "hash",
    positional: ["algorithm"],
    rest: "input",
    short: { encoding: "e", file: "f" },
    json: false,
  },
  execute: async (params) => {
    const hash = resolveAlgorithm(params.algorithm);
    const encoding = params.encoding ?? "hex";
    const options = { encoding, ...readParameters(hash, params) } as HashOptions;
    if (params.file === true) return printFiles(hash, params, options);
    const [only, ...more] = params.input;
    if (only !== undefined && more.length === 0) {
      return printDigest(hash.hash(readInput(only, params.inputEncoding), options));
    }
    const text = listEncoding(encoding);
    return printDigests(params.input, params.inputEncoding, (input) =>
      digestDetails(hash.hash(input, options), text),
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
    input: Type.Array(Type.String(), {
      minItems: 2,
      description:
        "Text to HMAC, or - for stdin, read byte for byte, then the key last; several texts get a line each under that key",
    }),
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
    ...hmacParameters,
  }),
  cli: {
    command: "hmac",
    positional: ["algorithm"],
    rest: "input",
    short: { encoding: "e" },
    json: false,
  },
  execute: (params) => {
    const hash = resolveAlgorithm(params.algorithm);
    if (!hash.info().hmac) {
      throw new InvalidOptionError("algorithm", hash.name(), "has no HMAC mode");
    }
    const texts = params.input.slice(0, -1);
    const key = decodeInput(params.input.at(-1) ?? "", params.keyEncoding ?? "utf8", "key");
    const encoding = params.encoding ?? "hex";
    const options = readParameters(hash, params, hmacParameters, HMAC_ONE_ROUND);
    const [only, ...more] = texts;
    if (only !== undefined && more.length === 0) {
      const input = readInput(only, params.inputEncoding);
      return printDigest(hash.hash(input, { ...options, encoding, key } as HashOptions));
    }
    const text = listEncoding(encoding);
    return printDigests(texts, params.inputEncoding, (input) =>
      digestDetails(hash.hash(input, { ...options, encoding: text, key } as HashOptions), text),
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
    input: Type.Array(Type.String(), {
      minItems: 2,
      description:
        "Text to hash, or - for stdin, read byte for byte, then the expected digest last; with several texts it tells which give it",
    }),
    inputEncoding,
    encoding: Type.Optional(
      Type.Enum(TEXT_ENCODINGS, {
        description: "Encoding of the expected digest: hex, base64, base64url",
      }),
    ),
    ...parameters,
  }),
  cli: { positional: ["algorithm"], rest: "input", short: { encoding: "e" } },
  execute: (params): ToolResult<VerifyDetails | VerifyList> => {
    const hash = resolveAlgorithm(params.algorithm);
    const encoding = params.encoding ?? "hex";
    const texts = params.input.slice(0, -1);
    const expected = (params.input.at(-1) ?? "").trim();
    if (expected === "") throw new InvalidOptionError("expected", "", "must not be empty");
    const expectedLength = assertExpected(expected, encoding).length;
    const options = readParameters(hash, params);
    assertDrawnOptions(hash.info(), options);
    const [only, ...more] = texts;
    if (only === undefined || more.length > 0) {
      return verifyList(hash, texts, params.inputEncoding, { encoding, ...options }, expected);
    }
    const result = hash.hash(readInput(only, params.inputEncoding), {
      encoding,
      ...options,
    } as HashOptions);
    const digest = String(result.digest);
    const match = digestMatches(result, expected);
    if (!match) process.exitCode = 1;
    const verdict: VerifyDetails = {
      ...digestDetails(result, encoding),
      expected,
      expectedLength,
      match,
    };
    const note = lengthNote(hash, options, [verdict]);
    const text = match
      ? `MATCH ${hash.name()} ${digest}`
      : [`MISMATCH ${hash.name()}`, `expected ${shown(expected)}`, `actual   ${digest}`]
          .concat(note === undefined ? [] : [note])
          .join("\n  ");
    return { content: [{ type: "text", text }], details: verdict };
  },
});

/**
 * Checks candidates against one digest in the lines `hashes_verify` gives, exit 1 if none match.
 *
 * @param hash - The algorithm.
 * @param texts - The inputs as given.
 * @param encoding - How to read them.
 * @param options - What to hash them with, the digest encoding among them.
 * @param expected - The expected digest.
 * @returns {ToolResult<VerifyList>} The verdicts.
 */
function verifyList(
  hash: Hash,
  texts: readonly string[],
  encoding: InputEncoding | undefined,
  options: Readonly<Record<string, ParameterValue>> & { readonly encoding: TextEncoding },
  expected: string,
): ToolResult<VerifyList> {
  const expectedLength = assertExpected(expected, options.encoding).length;
  const items = readInputs(texts, encoding).map((input) =>
    isBatchError(input)
      ? input
      : settled((): VerifyDetails => {
          const result = hash.hash(input, options as HashOptions);
          return {
            ...digestDetails(result, options.encoding),
            expected,
            expectedLength,
            match: digestMatches(result, expected),
          };
        }),
  );
  const note = lengthNote(hash, options, items);
  const { text, matches } = verifyListText(items, texts, hash.name(), expected, note);
  if (matches === 0) process.exitCode = 1;
  return { content: [{ type: "text", text }], details: { expected, matches, items } };
}

/**
 * Names a length mismatch in the CLI's words: both lengths, then the flag that fixes it.
 *
 * @param hash - The algorithm.
 * @param options - The options it ran with.
 * @param items - Every verdict, or the refusal of its input.
 * @returns {string | undefined} One line, or nothing when the lengths agree or an input matched.
 */
function lengthNote(
  hash: Hash,
  options: Readonly<Record<string, ParameterValue>>,
  items: readonly (VerifyDetails | BatchError)[],
): string | undefined {
  const mismatch = lengthMismatch(hash, options, items);
  if (mismatch === undefined) return undefined;
  const { expected, actual, fixes } = mismatch;
  const sizes = `lengths differ: expected is ${counted(expected, "byte")}, ${hash.name()} gave ${actual}`;
  return fixes.length > 0
    ? `${sizes}; ${fixes.map(flagText).join(" or ")} gives ${expected}, hashes identify names the other algorithms that do`
    : `${sizes}; hashes identify names the algorithms that give ${expected}`;
}

/**
 * Spells option values as the flags that set them, `keyLength` as `--key-length`.
 *
 * @param values - Option values by name.
 * @returns {string} The flags.
 */
function flagText(values: Readonly<Record<string, number | string>>): string {
  return Object.entries(values)
    .map(([name, value]) => `--${name.replaceAll(/(?<!^)[A-Z]/gu, "-$&").toLowerCase()} ${value}`)
    .join(" ");
}

/** The verdict on every candidate of a list. */
interface VerifyList {
  expected: string;
  matches: number;
  items: Array<VerifyDetails | BatchError>;
}

export const identifyCommand = defineTool({
  name: "hashes_identify",
  title: "Identify",
  description: "Guess which algorithms a hash may come from, by its prefix or its length",
  effect: "read",
  input: closed({
    digest: Type.Array(Type.String({ minLength: 1 }), {
      minItems: 1,
      description:
        "The hash: hex, base64, or a string such as $2b$... (quote it in the shell); several get a block each",
    }),
  }),
  cli: { command: "identify", rest: "digest" },
  execute: ({ digest }): ToolResult<DigestIdentity | { items: DigestIdentity[] }> => {
    const [only, ...more] = digest;
    if (only !== undefined && more.length === 0) {
      const identity = identifyDigest(only);
      const { heading, lines } = identityText(identity);
      process.stderr.write(`${heading}\n`);
      return found(lines, identity);
    }
    const items = identifyDigest(digest);
    const blocks = items.map((identity, index) => {
      const { heading, lines } = identityText(identity);
      return [quoted((digest[index] ?? "").trim()), heading, ...lines].join("\n");
    });
    if (items.some((identity) => identity.candidates.length === 0)) process.exitCode = 1;
    return { content: [{ type: "text", text: blocks.join("\n\n") }], details: { items } };
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
      description:
        "The digest, in hex unless --encoding says otherwise, or several split by commas and searched in one pass; the words follow it",
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
    const encoding = params.encoding ?? "hex";
    const digests = params.digest.split(",").map((digest) => digest.trim());
    const targets =
      digests.length === 1
        ? assertExpected(digests[0]!, encoding, "digest")
        : digests.map((digest, index) => assertExpected(digest, encoding, `digest ${index + 1}`));
    const progress = new Progress();
    const options: SearchDigestOptions = {
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
    };
    const result = Array.isArray(targets)
      ? searchDigest(targets, options)
      : searchDigest(targets, options);
    progress.clear();
    const { heading, lines } = searchText(result);
    for (const line of heading) process.stderr.write(`${line}\n`);
    if ("items" in result && result.items.some((item) => item.recipe === undefined)) {
      process.exitCode = 1;
    }
    return found(lines, result);
  },
});

/**
 * Hashes files by path: one digest alone, or a line each that `sha256sum -c` reads.
 *
 * @param hash - The algorithm.
 * @param params - The paths and how to read them.
 * @param options - What to hash with, the digest encoding among them.
 * @returns {Promise<ToolResult<unknown>>} The digest, or a line per file.
 */
async function printFiles(
  hash: Hash,
  params: Readonly<{ input: readonly string[]; inputEncoding?: InputEncoding }>,
  options: HashOptions,
): Promise<ToolResult<unknown>> {
  if (params.inputEncoding !== undefined) {
    throw new InvalidOptionError(
      "inputEncoding",
      params.inputEncoding,
      "reads text; --file hashes the file's bytes as they are",
    );
  }
  const fileOptions = { ...options, algorithm: hash.name() };
  const [only, ...more] = params.input;
  if (only !== undefined && more.length === 0)
    return printDigest(await hashFile(only, fileOptions));
  const text = listEncoding(options.encoding ?? "hex");
  const items: Array<DigestDetails | BatchError> = [];
  for (const path of params.input) {
    items.push(
      await settledAsync(async () => digestDetails(await hashFile(path, fileOptions), text)),
    );
  }
  assertOneSetting(items);
  const { about } = digestLines(items, params.input);
  process.stderr.write(`${counted(items.length, "file")}, ${about ?? "none hashed"}\n`);
  const lines = items.flatMap((item, index) => {
    const path = params.input[index] ?? "";
    if (!isBatchError(item)) return [plainLine({ path, digest: item.digest })];
    process.stderr.write(`ERROR  ${quoted(path)}  ${item.error}\n`);
    return [];
  });
  if (items.some(isBatchError)) process.exitCode = 1;
  return {
    content: lines.length > 0 ? [{ type: "text", text: lines.join("\n") }] : [],
    details: { items },
  };
}

/**
 * Refuses files whose digests need different options, such as a salt drawn per file.
 *
 * @param items - Every digest, or the refusal of its file.
 */
function assertOneSetting(items: readonly (DigestDetails | BatchError)[]): void {
  const settings = new Set(
    items.flatMap((item) => (isBatchError(item) ? [] : [JSON.stringify(item.options)])),
  );
  if (settings.size > 1) {
    throw new InvalidOptionError("salt", "drawn", "differs per file; pass one so every line fits");
  }
}

/**
 * The async `settled`.
 *
 * @param run - Hashes one file.
 * @returns {Promise<T | BatchError>} The result, or the reason there is none.
 */
async function settledAsync<T>(run: () => Promise<T>): Promise<T | BatchError> {
  try {
    return await run();
  } catch (error) {
    if (error instanceof HashError) return { error: error.message };
    throw error;
  }
}

const exclude = Type.Optional(
  Type.Array(Type.String({ minLength: 1 }), {
    description: 'Globs of paths to leave out, a JSON array such as ["node_modules/**", "*.log"]',
  }),
);

export const manifestCommand = defineTool({
  name: "hashes_manifest",
  title: "Manifest",
  description:
    "Write a checksum manifest of every regular file under a directory, sorted by path, in the tag format sha256sum -c reads",
  effect: "read",
  input: closed({
    algorithm,
    root: Type.Optional(
      Type.String({ minLength: 1, description: "Directory to list (default the current one)" }),
    ),
    output: Type.Optional(
      Type.String({
        minLength: 1,
        description: "File to write the manifest to, left out of it (default stdout)",
      }),
    ),
    exclude,
  }),
  cli: { positional: ["algorithm", "root"], short: { output: "o" }, json: false },
  execute: async (params): Promise<ToolResult<CreatedManifest>> => {
    const manifest = await createManifest({
      algorithm: params.algorithm,
      root: params.root,
      exclude: params.exclude,
      output: params.output ?? "/dev/stdout",
    });
    const skipped = manifest.skipped.length;
    const heading = `${counted(manifest.entries.length, "file")}, ${manifest.entries[0]?.algorithm}`;
    const left = skipped > 0 ? `, ${skipped} left out (symlinks and special files)` : "";
    process.stderr.write(`${heading}${left}\n`);
    if (params.output === undefined) process.stdout.write(manifest.text);
    else writeFileSync(params.output, manifest.text);
    return { content: [], details: manifest };
  },
});

/** How each status reads in the report, padded to one width. */
const STATUS_WORDS: Readonly<Record<ManifestResult["status"], string>> = {
  ok: "OK        ",
  mismatch: "MISMATCH  ",
  missing: "MISSING   ",
  unreadable: "UNREADABLE",
  extra: "EXTRA     ",
};

/**
 * One report line, the path in JSON quotes.
 *
 * @param result - The verdict on one file.
 * @returns {string} The line.
 */
function resultLine(result: Readonly<ManifestResult>): string {
  const reason = result.reason === undefined ? "" : `  ${result.reason}`;
  return `${STATUS_WORDS[result.status]}  ${quoted(result.path)}${reason}`;
}

/**
 * Reads the manifest file, or stdin for `-`, as strict UTF-8.
 *
 * @param path - The path as given.
 * @returns {string} The manifest text.
 */
function readManifest(path: string): string {
  let bytes: Uint8Array;
  try {
    bytes = readFileSync(path === "-" ? 0 : path);
  } catch (error) {
    const code = error instanceof Error && "code" in error ? String(error.code) : String(error);
    throw new HashError(`Can't read the manifest ${quoted(path)}: ${code}`);
  }
  try {
    return new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(bytes);
  } catch {
    throw new HashError(`The manifest ${quoted(path)} is not UTF-8, so its paths can't be trusted`);
  }
}

export const checkCommand = defineTool({
  name: "hashes_check",
  title: "Check",
  description:
    "Check the files a checksum manifest lists, exit 1 on a mismatched, missing or unreadable one",
  effect: "read",
  input: closed({
    manifest: Type.String({
      minLength: 1,
      description: "The manifest: tag lines, or sha256sum lines with --algorithm; - for stdin",
    }),
    root: Type.Optional(
      Type.String({
        minLength: 1,
        description: "Directory the paths are relative to (default the current one)",
      }),
    ),
    algorithm: Type.Optional(
      Type.String({ minLength: 1, description: "Algorithm of untagged sha256sum lines" }),
    ),
    strict: Type.Optional(
      Type.Boolean({ description: "Also fail on files under the root the manifest doesn't list" }),
    ),
    exclude,
    quiet: Type.Optional(Type.Boolean({ description: "Print only the files that fail" })),
  }),
  cli: { positional: ["manifest", "root"], short: { algorithm: "a", quiet: "q" } },
  execute: async (params): Promise<ToolResult<ManifestCheck>> => {
    const source = params.manifest === "-" ? "/dev/stdin" : params.manifest;
    const check = await checkManifest(readManifest(params.manifest), {
      root: params.root,
      algorithm: params.algorithm,
      strict: params.strict,
      exclude: params.exclude,
      manifest: source,
    });
    const failed = check.results.filter((result) => result.status !== "ok");
    const shown = params.quiet === true ? failed : check.results;
    process.stderr.write(
      check.ok
        ? `OK: ${counted(check.results.length, "file")} match\n`
        : `FAILED: ${failed.length} of ${counted(check.results.length, "file")}\n`,
    );
    if (!check.ok) process.exitCode = 1;
    const lines = shown.map(resultLine);
    return {
      content: lines.length > 0 ? [{ type: "text", text: lines.join("\n") }] : [],
      details: check,
    };
  },
});

/** Every command of the CLI's own, each in the place of the tool command it shares a name with. */
export const cliCommands = [
  hashCommand,
  hmacCommand,
  verifyCommand,
  identifyCommand,
  searchCommand,
  manifestCommand,
  checkCommand,
];
