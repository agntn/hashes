/**
 * Tool executors shared by the MCP server, the AI SDK tools and the Pi and OMP extensions.
 *
 * Each executor returns the text a caller reads plus the structured details the agent harnesses
 * attach to the call. An MCP client sees only the text, so every fact needed for a follow-up call
 * (the salt a KDF drew, its cost parameters) has to be in it. Every bound the schemas declare is
 * enforced here again, because a host is free to skip schema validation.
 */

import type { Static } from "@agntn/tools";
import { decodeInput, parameterText, toBytes } from "./core/digest.ts";
import { HashError, quoted, shown } from "./core/errors.ts";
import { checkedParameters, parameterOptions, type ParameterValue } from "./core/options.ts";
import { algorithmInfos } from "./core/resolve.ts";
import { extendDigest, secretLengths } from "./core/extend.ts";
import { identifyDigest, identityText, type DigestIdentity } from "./core/identify.ts";
import {
  searchDigest,
  searchText,
  type DigestSearch,
  type DigestSearchBatch,
  type SearchCase,
  type SearchChain,
  type SearchDigestOptions,
} from "./core/search.ts";
import { assertDrawnOptions, assertExpected } from "./core/verify.ts";
import {
  InvalidOptionError,
  MissingOptionError,
  digestMatches,
  resolveAlgorithm,
  type AlgorithmInfo,
  type Hash,
  type HashInput,
  type HashOptions,
  type HashResult,
} from "./index.ts";
import {
  DIGEST_PATTERN,
  INPUT_ENCODINGS,
  MAX_ALGORITHM_LENGTH,
  MAX_BATCH_DIGESTS,
  MAX_BATCH_INPUTS,
  MAX_EXPECTED_LENGTH,
  MAX_FAMILY_LENGTH,
  MAX_INPUT_LENGTH,
  MAX_KEY_LENGTH,
  MAX_PARAMETER_LENGTH,
  MAX_PARAMETERS,
  MAX_ARGON2_WORK,
  MAX_FORGED_LENGTH,
  MAX_JOINER_LENGTH,
  MAX_SEARCH_ALGORITHMS,
  MAX_SEARCH_BYTES,
  MAX_SEARCH_HASHES,
  MAX_SEARCH_JOINERS,
  MAX_SEARCH_ROUNDS,
  MAX_SEARCH_WORDS,
  MAX_SECRET_LENGTH,
  MAX_SECRET_LENGTHS,
  MAX_SCRYPT_MEMORY,
  MAX_WORD_LENGTH,
  PARAMETER_LIMITS,
  PARAMETER_NAME_PATTERN,
  SALT_PATTERN,
  SEARCH_CASES,
  SEARCH_CHAINS,
  TEXT_ENCODINGS,
  ZERO_PARAMETERS,
} from "../packages/shared/tool-contract.ts";
import type { toolSchemas } from "../packages/shared/tool-schemas.ts";

export * from "../packages/shared/tool-contract.ts";
export type { DigestCandidate, DigestIdentity } from "./core/identify.ts";
export type {
  DigestRecipe,
  DigestSearch,
  DigestSearchBatch,
  DigestSearchItem,
  SearchScope,
} from "./core/search.ts";

/** Text for the model plus details for the harness, shared by every tool surface. */
export interface ToolResult<Details> {
  content: Array<{ type: "text"; text: string }>;
  details: Details;
  /** Set when not one input of a list could be hashed. */
  isError?: boolean;
}

/** Encodings a tool can return: text only, since a tool answers in text. */
export type TextEncoding = (typeof TEXT_ENCODINGS)[number];

/** How a tool reads its input: text as UTF-8, or bytes written in hex or base64. */
export type InputEncoding = (typeof INPUT_ENCODINGS)[number];

export type ToolName = keyof typeof toolSchemas;

/** Every argument each tool takes, pinned to the schemas by a test; anything else is rejected. */
export const TOOL_ARGUMENTS: Record<ToolName, readonly string[]> = {
  hashes_compute: ["algorithm", "input", "inputEncoding", "encoding", "salt", "parameters"],
  hashes_hmac_compute: ["algorithm", "input", "inputEncoding", "key", "keyEncoding", "encoding"],
  hashes_verify: [
    "algorithm",
    "input",
    "inputEncoding",
    "expected",
    "encoding",
    "salt",
    "parameters",
  ],
  hashes_digest_extend: [
    "algorithm",
    "digest",
    "message",
    "messageEncoding",
    "suffix",
    "suffixEncoding",
    "secretLength",
    "secretLengthMax",
  ],
  hashes_digest_identify: ["digest"],
  hashes_digest_search: [
    "digest",
    "encoding",
    "words",
    "minWords",
    "maxWords",
    "joiners",
    "cases",
    "algorithms",
    "rounds",
    "chains",
  ],
  hashes_algorithms: ["category", "family", "algorithm"],
};

/** A tool's arguments as its schema declares them, read-only down to nested objects. */
type ReadonlyValue<V> = V extends object ? Readonly<V> : V;
type Arguments<T> = { readonly [K in keyof T]: ReadonlyValue<T[K]> };

export type HashComputeParams = Arguments<Static<typeof toolSchemas.hashes_compute>>;
export type HashHmacParams = Arguments<Static<typeof toolSchemas.hashes_hmac_compute>>;
export type HashVerifyParams = Arguments<Static<typeof toolSchemas.hashes_verify>>;
export type HashDigestExtendParams = Arguments<Static<typeof toolSchemas.hashes_digest_extend>>;
export type HashDigestIdentifyParams = Arguments<Static<typeof toolSchemas.hashes_digest_identify>>;
export type HashDigestSearchParams = Arguments<Static<typeof toolSchemas.hashes_digest_search>>;
export type HashAlgorithmsParams = Arguments<Static<typeof toolSchemas.hashes_algorithms>>;

export interface DigestDetails {
  algorithm: string;
  operation: HashResult["operation"];
  encoding: TextEncoding;
  digest: string;
  digestLength: number;
  options: Record<string, unknown>;
}

export interface VerifyDetails extends DigestDetails {
  match: boolean;
  expected: string;
}

/** One forged message, its bytes in hex. */
export interface Extension {
  secretLength: number;
  digest: string;
  message: string;
  padding: string;
}

export interface ExtendDetails {
  algorithm: string;
  extensions: Extension[];
}

/** An input of a list that has no digest, and why. */
export interface BatchError {
  error: string;
}

/** The digest of every input of a list, in the order given. */
export interface DigestBatchDetails {
  items: Array<DigestDetails | BatchError>;
}

/** How every candidate input of a list compares with the one expected digest. */
export interface VerifyBatchDetails {
  expected: string;
  matches: number;
  items: Array<VerifyDetails | BatchError>;
}

/** The identity of every hash of a list, in the order given. */
export interface IdentifyBatchDetails {
  items: DigestIdentity[];
}

export interface AlgorithmsDetails {
  algorithms: AlgorithmInfo[];
}

const saltPattern = new RegExp(SALT_PATTERN);
const digestPattern = new RegExp(DIGEST_PATTERN);
const parameterName = new RegExp(PARAMETER_NAME_PATTERN);

/**
 * Rejects any key the tool does not take. A misspelled optional argument would otherwise be
 * dropped and change the answer without a sign: `salt_hex` would hash with a fresh random salt.
 *
 * @param tool - The tool the arguments are for.
 * @param params - The arguments as the host passed them.
 */
export function assertArguments(tool: ToolName, params: Readonly<object>): void {
  const accepted = TOOL_ARGUMENTS[tool];
  for (const key of Object.keys(params)) {
    if (!accepted.includes(key)) {
      throw new InvalidOptionError(key, "(unknown)", `${tool} takes only ${accepted.join(", ")}`);
    }
  }
}

/**
 * Checks a required or optional string argument against its maximum length.
 *
 * @param name - Argument name, for the error.
 * @param value - The value as passed.
 * @param maxLength - Longest accepted value.
 * @returns {string} The value.
 */
function textArgument(name: string, value: unknown, maxLength: number): string {
  if (typeof value !== "string") throw new MissingOptionError(name);
  if (value.length > maxLength) {
    throw new InvalidOptionError(name, `${value.length} characters`, `at most ${maxLength}`);
  }
  return value;
}

/**
 * Checks the optional encoding argument.
 *
 * @param value - The value as passed.
 * @returns {TextEncoding} The encoding, `hex` when omitted.
 */
function encodingArgument(value: unknown): TextEncoding {
  if (value === undefined) return "hex";
  if (typeof value === "string" && (TEXT_ENCODINGS as readonly string[]).includes(value)) {
    return value as TextEncoding;
  }
  throw new InvalidOptionError("encoding", value, `use one of ${TEXT_ENCODINGS.join(", ")}`);
}

/**
 * Reads a checked text argument as utf8 text, or as the bytes its hex or base64 spells.
 *
 * @param name - The text argument, for the error.
 * @param text - Its checked value.
 * @param encodingName - The encoding argument, for the error.
 * @param encoding - The encoding argument as passed.
 * @returns {HashInput} Text, or the decoded bytes.
 */
function decodedArgument(
  name: string,
  text: string,
  encodingName: string,
  encoding: unknown,
): HashInput {
  if (encoding === undefined) return text;
  if (typeof encoding === "string" && (INPUT_ENCODINGS as readonly string[]).includes(encoding)) {
    return decodeInput(text, encoding as InputEncoding, name);
  }
  throw new InvalidOptionError(encodingName, encoding, `use one of ${INPUT_ENCODINGS.join(", ")}`);
}

/**
 * Checks the input and reads it as its encoding says.
 *
 * @param value - The input as passed.
 * @param encoding - The inputEncoding argument as passed.
 * @returns {HashInput} What to hash.
 */
function inputArgument(value: unknown, encoding: unknown): HashInput {
  const text = textArgument("input", value, MAX_INPUT_LENGTH);
  return decodedArgument("input", text, "inputEncoding", encoding);
}

/** One input, or a list of them hashed with the same options. */
type Inputs =
  | { readonly list: false; readonly text: string; readonly value: HashInput }
  | {
      readonly list: true;
      readonly texts: readonly string[];
      readonly values: readonly HashInput[];
    };

/**
 * Reads one input or a list, which shares the length limit of a single input.
 *
 * @param value - The input or the list as passed.
 * @param encoding - The inputEncoding argument as passed.
 * @returns {Inputs} What to hash, with the text of each entry for its line.
 */
function inputsArgument(value: unknown, encoding: unknown): Inputs {
  if (!Array.isArray(value)) {
    const input = inputArgument(value, encoding);
    return { list: false, text: value as string, value: input };
  }
  const texts = listArgument("input", value, MAX_BATCH_INPUTS, MAX_INPUT_LENGTH) ?? [];
  const total = texts.reduce((sum, text) => sum + text.length, 0);
  if (total > MAX_INPUT_LENGTH) {
    throw new InvalidOptionError(
      "input",
      `${total} characters in all`,
      `a list takes at most ${MAX_INPUT_LENGTH}`,
    );
  }
  const values = texts.map((text, index) =>
    decodedArgument(`input ${index + 1}`, text, "inputEncoding", encoding),
  );
  return { list: true, texts, values };
}

/**
 * Checks the HMAC key and reads it as its encoding says.
 *
 * @param value - The key as passed.
 * @param encoding - The keyEncoding argument as passed.
 * @returns {HashInput} The key.
 */
function keyArgument(value: unknown, encoding: unknown): HashInput {
  const text = textArgument("key", value, MAX_KEY_LENGTH);
  return decodedArgument("key", text, "keyEncoding", encoding);
}

/**
 * Checks the optional salt against the algorithm: one that declares a salt option takes it, any
 * other refuses it instead of hashing without it.
 *
 * @param algorithm - The resolved algorithm.
 * @param value - The salt as passed.
 * @returns {string | undefined} The salt in hex, when given.
 */
function saltArgument(value: unknown): string | undefined {
  if (value === undefined) return undefined;
  if (typeof value !== "string" || !saltPattern.test(value)) {
    throw new InvalidOptionError("salt", value, "must be 1 to 256 bytes in hex");
  }
  return value;
}

/**
 * Names the argument that takes an option a model put into `parameters` instead.
 *
 * @param name - The parameter name.
 * @param hmac - Whether the algorithm has an HMAC mode.
 * @returns {string | undefined} Where the option goes, or nothing for a real parameter.
 */
function argumentFor(name: string, hmac: boolean): string | undefined {
  if (name === "salt" || name === "encoding") return `pass the ${name} as the ${name} argument`;
  if (name === "key" && hmac) return "pass the key to hashes_hmac_compute";
  return undefined;
}

/**
 * Checks what the schema declares about `parameters` again: how many, the names, the length of
 * a text value, and that the salt, the encoding and an HMAC key come through their own arguments.
 *
 * @param given - The parameters as passed.
 * @param hmac - Whether the algorithm has an HMAC mode.
 */
function assertParameterEntries(given: Readonly<Record<string, unknown>>, hmac: boolean): void {
  const entries = Object.entries(given);
  if (entries.length > MAX_PARAMETERS) {
    throw new InvalidOptionError("parameters", "(object)", `at most ${MAX_PARAMETERS} entries`);
  }
  for (const [name, value] of entries) {
    if (!parameterName.test(name)) {
      throw new InvalidOptionError(
        "parameters",
        name,
        "names are letters and digits, starting with a letter",
      );
    }
    const redirect = argumentFor(name, hmac);
    if (redirect !== undefined) throw new InvalidOptionError("parameters", name, redirect);
    if (typeof value === "string" && value.length > MAX_PARAMETER_LENGTH) {
      throw new InvalidOptionError(
        name,
        `${value.length} characters`,
        `at most ${MAX_PARAMETER_LENGTH}`,
      );
    }
  }
}

/**
 * Checks a numeric parameter against its tool limit.
 *
 * @param name - The parameter.
 * @param value - Its value.
 */
function assertWithinLimit(name: string, value: ParameterValue): void {
  const limit = Object.hasOwn(PARAMETER_LIMITS, name) ? PARAMETER_LIMITS[name] : undefined;
  const floor = ZERO_PARAMETERS.includes(name) ? 0 : 1;
  if (limit !== undefined && typeof value === "number" && (value < floor || value > limit)) {
    throw new InvalidOptionError(name, value, `must be ${floor} to ${limit} in a tool call`);
  }
}

/**
 * Checks the salt and the optional parameters against what the algorithm declares, and the cost
 * a model may choose against the tool limits. The salt joins them, so an algorithm without a salt
 * option refuses it by the same rule as any other undeclared parameter.
 *
 * @param algorithm - The resolved algorithm.
 * @param salt - The salt argument as passed.
 * @param parameters - The parameters argument as passed.
 * @returns {Record<string, ParameterValue>} The options to hash with.
 */
function algorithmOptions(
  algorithm: Hash,
  salt: unknown,
  parameters: unknown,
): Record<string, ParameterValue> {
  if (parameters !== undefined && (typeof parameters !== "object" || parameters === null)) {
    throw new InvalidOptionError("parameters", parameters, "must be an object of option values");
  }
  const given = { ...(parameters as Readonly<Record<string, unknown>> | undefined) };
  assertParameterEntries(given, algorithm.info().hmac);
  const hexSalt = saltArgument(salt);
  if (hexSalt !== undefined) given["salt"] = hexSalt;
  const options = checkedParameters(algorithm, given);
  for (const [name, value] of Object.entries(options)) assertWithinLimit(name, value);
  assertScryptMemory(algorithm, options);
  assertArgon2Work(algorithm, options);
  return options;
}

/**
 * Reads a cost the call sets, or the algorithm's declared default when it leaves it out.
 *
 * @param algorithm - The resolved algorithm.
 * @param options - The options as given.
 * @returns {Map<string, number>} Every declared option with its value as a number.
 */
function costs(algorithm: Hash, options: Readonly<Record<string, unknown>>): Map<string, number> {
  return new Map(
    parameterOptions(algorithm).map((option) => [
      option.name,
      Number(options[option.name] ?? option.default),
    ]),
  );
}

/**
 * Bytes a call's KDF fills: the scrypt block table or the Argon2 memory, 0 for anything else.
 * A cost that's neither a number nor text counts as its default, and the schema refuses it after.
 *
 * @param args - The arguments of a tool call, read for `algorithm` and `parameters`.
 * @returns {number} The bytes, or 0 when the call names no KDF it can read.
 */
export function kdfMemory(args: Readonly<Record<string, unknown>>): number {
  const algorithm = knownAlgorithm(args["algorithm"]);
  if (algorithm === undefined) return 0;
  const { parameters } = args;
  const given = typeof parameters === "object" && parameters !== null ? parameters : {};
  const numbers = Object.entries(given as Readonly<Record<string, unknown>>).filter(
    ([, value]) => typeof value === "number" || typeof value === "string",
  );
  const cost = costs(algorithm, Object.fromEntries(numbers));
  const at = (name: string): number => cost.get(name) ?? 0;
  const memory = cost.has("N") ? 128 * at("r") * at("N") : 1024 * at("memory");
  return Number.isFinite(memory) ? memory : 0;
}

/**
 * Resolves a name the way a call does, or nothing when no algorithm answers to it.
 *
 * @param name - The name as passed.
 * @returns {Hash | undefined} The algorithm.
 */
function knownAlgorithm(name: unknown): Hash | undefined {
  if (typeof name !== "string") return undefined;
  try {
    return resolveAlgorithm(name);
  } catch {
    return undefined;
  }
}

/**
 * Keeps a scrypt call within `MAX_SCRYPT_MEMORY`, reading the costs the call leaves out from the
 * algorithm's declared defaults.
 *
 * @param algorithm - The resolved algorithm.
 * @param options - The checked options.
 */
function assertScryptMemory(
  algorithm: Hash,
  options: Readonly<Record<string, ParameterValue>>,
): void {
  const all = costs(algorithm, options);
  if (!(all.has("N") && all.has("r") && all.has("p"))) return;
  const cost = (name: string): number => all.get(name) ?? 0;
  const memory = 128 * cost("r") * cost("N");
  if (memory > MAX_SCRYPT_MEMORY) {
    throw new InvalidOptionError(
      "N",
      cost("N"),
      `with r=${cost("r")} needs ${memory} bytes of blocks, over ${MAX_SCRYPT_MEMORY} in a tool call`,
    );
  }
}

/**
 * Keeps an Argon2 call within `MAX_ARGON2_WORK`, since its time grows with memory times passes,
 * reading the costs the call leaves out from the algorithm's declared defaults.
 *
 * @param algorithm - The resolved algorithm.
 * @param options - The checked options.
 */
function assertArgon2Work(
  algorithm: Hash,
  options: Readonly<Record<string, ParameterValue>>,
): void {
  const all = costs(algorithm, options);
  if (!(all.has("memory") && all.has("iterations"))) return;
  const cost = (name: string): number => all.get(name) ?? 0;
  const work = cost("memory") * cost("iterations");
  if (work > MAX_ARGON2_WORK) {
    throw new InvalidOptionError(
      "iterations",
      cost("iterations"),
      `with memory=${cost("memory")} fills ${work} KiB, over ${MAX_ARGON2_WORK} in a tool call`,
    );
  }
}

/** What one input of a list costs, against the most one call may spend. */
interface BatchWork {
  readonly name: string;
  readonly value: number;
  readonly work: number;
  readonly limit: number;
}

/**
 * Reads the tool limit of a cost parameter.
 *
 * @param name - The parameter.
 * @returns {number} Its limit.
 */
function limitOf(name: string): number {
  return PARAMETER_LIMITS[name] ?? 1;
}

/**
 * Prices one input against the limit that bounds its algorithm's time.
 *
 * @param algorithm - The resolved algorithm.
 * @param options - The checked options.
 * @returns {BatchWork | undefined} The cost and its limit, or nothing when it's free.
 */
function batchWork(
  algorithm: Hash,
  options: Readonly<Record<string, ParameterValue>>,
): BatchWork | undefined {
  const all = costs(algorithm, options);
  const at = (name: string): number => all.get(name) ?? 0;
  if (all.has("N")) {
    const work = 128 * at("N") * at("r") * at("p");
    return { name: "N", value: at("N"), work, limit: MAX_SCRYPT_MEMORY * limitOf("p") };
  }
  if (all.has("memory")) {
    const work = at("memory") * at("iterations");
    return { name: "memory", value: at("memory"), work, limit: MAX_ARGON2_WORK };
  }
  if (all.has("cost")) {
    return { name: "cost", value: at("cost"), work: 2 ** at("cost"), limit: 2 ** limitOf("cost") };
  }
  const name = ["iterations", "rounds"].find((each) => all.has(each));
  if (name === undefined) return undefined;
  return { name, value: at(name), work: at(name), limit: limitOf(name) };
}

/**
 * Keeps a list at one call's cost, so 64 inputs can't buy 64 times the PBKDF2 iterations.
 *
 * @param algorithm - The resolved algorithm.
 * @param options - The checked options.
 * @param count - How many inputs the call hashes.
 */
function assertBatchCost(
  algorithm: Hash,
  options: Readonly<Record<string, ParameterValue>>,
  count: number,
): void {
  if (count === 1) return;
  const batch = batchWork(algorithm, options);
  if (batch === undefined || batch.work * count <= batch.limit) return;
  const fits = Math.max(1, Math.floor(batch.limit / batch.work));
  throw new InvalidOptionError(
    "input",
    `${count} inputs`,
    `with ${batch.name} ${batch.value} one call hashes at most ${counted(fits, "input")}; split the list or lower ${batch.name}`,
  );
}

/**
 * Counts a noun in English.
 *
 * @param count - How many.
 * @param noun - The noun in the singular.
 * @returns {string} Such as `1 input` or `3 inputs`.
 */
function counted(count: number, noun: string): string {
  return `${count} ${noun}${count === 1 ? "" : "s"}`;
}

/**
 * Resolves the algorithm argument.
 *
 * @param value - The name as passed.
 * @returns {Hash} The algorithm.
 */
function algorithmArgument(value: unknown): Hash {
  return resolveAlgorithm(textArgument("algorithm", value, MAX_ALGORITHM_LENGTH));
}

/**
 * Turns a text-encoded result into the details every digest tool returns.
 *
 * @param result - The computed hash.
 * @param encoding - Its text encoding.
 * @returns {DigestDetails} The details.
 */
function digestDetails(result: HashResult, encoding: TextEncoding): DigestDetails {
  return {
    algorithm: result.algorithm,
    operation: result.operation,
    encoding,
    digest: String(result.digest),
    digestLength: result.digestLength,
    options: result.options,
  };
}

/**
 * Describes a digest in one line after the digest itself.
 *
 * @param details - The digest details.
 * @returns {string} The digest, then its algorithm, encoding, length and parameters.
 */
function digestText(details: DigestDetails): string {
  return `${details.digest}\n${aboutText(details, details.options)}`;
}

/**
 * Names the algorithm, encoding, length and the given parameters of a digest.
 *
 * @param details - The digest details.
 * @param options - The parameters to name.
 * @returns {string} One line.
 */
function aboutText(details: DigestDetails, options: Readonly<Record<string, unknown>>): string {
  const parameters = parameterText(options);
  const label = details.operation === "hmac" ? `HMAC-${details.algorithm}` : details.algorithm;
  const about = `${label}, ${details.encoding}, ${details.digestLength} bytes`;
  return parameters ? `${about}, ${parameters}` : about;
}

/** Longest stretch of an input its line repeats. */
const LABEL_LENGTH = 64;

/**
 * Quotes an input for its line in a list, so a space or a line feed in it stays visible.
 *
 * @param text - The input as passed.
 * @returns {string} The input in quotes, cut after `LABEL_LENGTH` characters.
 */
function inputLabel(text: string): string {
  if (text.length <= LABEL_LENGTH) return quoted(text);
  return `${quoted(text.slice(0, LABEL_LENGTH))}… (${text.length} characters)`;
}

/**
 * Turns the refusal of one input into its own entry; anything but a `HashError` is a bug.
 *
 * @param run - Hashes the input.
 * @returns {T | BatchError} The result, or the reason there is none.
 */
function settled<T>(run: () => T): T | BatchError {
  try {
    return run();
  } catch (error) {
    if (error instanceof HashError) return { error: error.message };
    throw error;
  }
}

/**
 * The options every digest of a list shares, so the heading names them once.
 *
 * @param items - The digests.
 * @returns {Record<string, unknown>} The shared options; a drawn salt differs and stays out.
 */
function sharedOptions(items: readonly DigestDetails[]): Record<string, unknown> {
  const [first, ...rest] = items;
  if (first === undefined) return {};
  return Object.fromEntries(
    Object.entries(first.options).filter(([name, value]) =>
      rest.every((item) => String(item.options[name]) === String(value)),
    ),
  );
}

/**
 * The options of one digest that the heading of its list leaves out.
 *
 * @param details - The digest.
 * @param shared - What the heading names.
 * @returns {string} Its own parameters, or an empty string.
 */
function ownText(details: DigestDetails, shared: Readonly<Record<string, unknown>>): string {
  return parameterText(
    Object.fromEntries(
      Object.entries(details.options).filter(([name]) => !Object.hasOwn(shared, name)),
    ),
  );
}

/**
 * Lays out a list the way `sha256sum` does, digest then input, under one heading.
 *
 * @param items - Every entry, hashed or refused.
 * @param texts - The inputs as passed, for their labels.
 * @param prefixes - What goes before each digest, such as its verdict.
 * @returns {string[]} The heading's parameters and one line per input.
 */
function digestLines(
  items: readonly (DigestDetails | BatchError)[],
  texts: readonly string[],
  prefixes: readonly string[] = [],
): { about: string | undefined; lines: string[] } {
  const digests = items.filter((item): item is DigestDetails => !("error" in item));
  const shared = sharedOptions(digests);
  const [first] = digests;
  const lines = items.map((item, index) => {
    const label = inputLabel(texts[index] ?? "");
    if ("error" in item) return `ERROR  ${label}  ${item.error}`;
    const own = ownText(item, shared);
    const digest = `${prefixes[index] ?? ""}${item.digest}`;
    return [digest, label, ...(own ? [own] : [])].join("  ");
  });
  return { about: first === undefined ? undefined : aboutText(first, shared), lines };
}

/**
 * The answer to a list of inputs: a heading, a line per input, and an error only when none hashed.
 *
 * @param text - The heading and the lines.
 * @param details - The details for the harness.
 * @param hashedAny - Whether any input got a digest.
 * @returns {ToolResult<T>} The result.
 */
function listResult<T>(text: string, details: T, hashedAny: boolean): ToolResult<T> {
  const content = [{ type: "text" as const, text }];
  return hashedAny ? { content, details } : { content, details, isError: true };
}

/**
 * Hashes text with any registered algorithm. A KDF without a salt draws a random one and the
 * answer names it, since the digest cannot be reproduced without it.
 *
 * A list of inputs gets a digest each, with the same options.
 *
 * @param params - Algorithm, input or inputs and their encoding, digest encoding and, for a KDF,
 *   the salt in hex.
 * @returns {ToolResult<DigestDetails | DigestBatchDetails>} The digest, or one per input.
 */
export function hashCompute(
  params: HashComputeParams & { readonly input: string },
): ToolResult<DigestDetails>;
export function hashCompute(
  params: HashComputeParams,
): ToolResult<DigestDetails | DigestBatchDetails>;
export function hashCompute(
  params: HashComputeParams,
): ToolResult<DigestDetails | DigestBatchDetails> {
  assertArguments("hashes_compute", params);
  const algorithm = algorithmArgument(params.algorithm);
  const inputs = inputsArgument(params.input, params.inputEncoding);
  const encoding = encodingArgument(params.encoding);
  const options = algorithmOptions(algorithm, params.salt, params.parameters);
  const digest = (input: HashInput): DigestDetails =>
    digestDetails(algorithm.hash(input, { encoding, ...options } as HashOptions), encoding);
  if (!inputs.list) return digestResult(digest(inputs.value));
  assertBatchCost(algorithm, options, inputs.values.length);
  return digestListResult(
    inputs.values.map((input) => settled(() => digest(input))),
    inputs.texts,
  );
}

/**
 * The answer to one input: the digest, then what made it.
 *
 * @param details - The digest.
 * @returns {ToolResult<DigestDetails>} The result.
 */
function digestResult(details: DigestDetails): ToolResult<DigestDetails> {
  return { content: [{ type: "text", text: digestText(details) }], details };
}

/**
 * The answer to a list of inputs: what made the digests once, then a line per input.
 *
 * @param items - Every entry, hashed or refused.
 * @param texts - The inputs as passed.
 * @returns {ToolResult<DigestBatchDetails>} The result.
 */
function digestListResult(
  items: readonly (DigestDetails | BatchError)[],
  texts: readonly string[],
): ToolResult<DigestBatchDetails> {
  const { about, lines } = digestLines(items, texts);
  const heading = `${counted(items.length, "input")}, ${about ?? "none hashed"}`;
  return listResult([heading, ...lines].join("\n"), { items: [...items] }, about !== undefined);
}

/**
 * Computes an HMAC with an algorithm that offers it.
 *
 * A list of inputs gets an HMAC each under the same key.
 *
 * @param params - Algorithm, input or inputs and their encoding, key and its encoding, digest
 *   encoding.
 * @returns {ToolResult<DigestDetails | DigestBatchDetails>} The HMAC, or one per input.
 */
export function hashHmac(
  params: HashHmacParams & { readonly input: string },
): ToolResult<DigestDetails>;
export function hashHmac(params: HashHmacParams): ToolResult<DigestDetails | DigestBatchDetails>;
export function hashHmac(params: HashHmacParams): ToolResult<DigestDetails | DigestBatchDetails> {
  assertArguments("hashes_hmac_compute", params);
  const algorithm = algorithmArgument(params.algorithm);
  const inputs = inputsArgument(params.input, params.inputEncoding);
  const key = keyArgument(params.key, params.keyEncoding);
  const encoding = encodingArgument(params.encoding);
  if (!algorithm.info().hmac) {
    throw new InvalidOptionError("algorithm", algorithm.name(), "has no HMAC mode");
  }
  const tag = (input: HashInput): DigestDetails =>
    digestDetails(algorithm.hash(input, { encoding, key }), encoding);
  if (!inputs.list) return digestResult(tag(inputs.value));
  return digestListResult(
    inputs.values.map((input) => settled(() => tag(input))),
    inputs.texts,
  );
}

/**
 * Hashes the input and compares the digest with an expected one, in constant time. Hex ignores
 * case; base64 and base64url do not. An expected digest that is not valid in its encoding is an
 * error, not a mismatch. A KDF needs the salt the expected digest was made with.
 *
 * A list of candidate inputs gets a verdict each, so one call tells which of them it was.
 *
 * @param params - Algorithm, input or inputs and their encoding, expected digest and its encoding
 *   and, for a KDF, the salt.
 * @returns {ToolResult<VerifyDetails | VerifyBatchDetails>} Whether the digests match, with both
 *   of them, or a verdict per input.
 */
export function hashVerify(
  params: HashVerifyParams & { readonly input: string },
): ToolResult<VerifyDetails>;
export function hashVerify(
  params: HashVerifyParams,
): ToolResult<VerifyDetails | VerifyBatchDetails>;
export function hashVerify(
  params: HashVerifyParams,
): ToolResult<VerifyDetails | VerifyBatchDetails> {
  assertArguments("hashes_verify", params);
  const algorithm = algorithmArgument(params.algorithm);
  const inputs = inputsArgument(params.input, params.inputEncoding);
  const expected = textArgument("expected", params.expected, MAX_EXPECTED_LENGTH).trim();
  if (expected === "") throw new InvalidOptionError("expected", "", "must not be empty");
  const encoding = encodingArgument(params.encoding);
  assertExpected(expected, encoding);
  const options = algorithmOptions(algorithm, params.salt, params.parameters);
  assertDrawnOptions(algorithm.info(), options);
  const verdict = (input: HashInput): VerifyDetails => {
    const result = algorithm.hash(input, { encoding, ...options } as HashOptions);
    return { ...digestDetails(result, encoding), expected, match: digestMatches(result, expected) };
  };
  if (!inputs.list) return verifyResult(verdict(inputs.value), algorithm.name());
  assertBatchCost(algorithm, options, inputs.values.length);
  const items = inputs.values.map((input) => settled(() => verdict(input)));
  const matches = items.filter((item) => !("error" in item) && item.match).length;
  const verdicts = items.map((item) =>
    "match" in item && item.match ? "match     " : "mismatch  ",
  );
  const { about, lines } = digestLines(items, inputs.texts, verdicts);
  const heading =
    matches > 0
      ? `MATCH: ${matches} of ${counted(items.length, "input")} ${matches === 1 ? "gives" : "give"} the expected ${algorithm.name()} digest`
      : `MISMATCH: none of ${counted(items.length, "input")} gives the expected ${algorithm.name()} digest`;
  const text = [heading, `expected ${shown(expected)}`, ...lines].join("\n");
  return listResult(text, { expected, matches, items }, about !== undefined);
}

/**
 * The answer to one input: MATCH with the digest, or MISMATCH with both.
 *
 * @param details - The verdict.
 * @param name - The algorithm.
 * @returns {ToolResult<VerifyDetails>} The result.
 */
function verifyResult(details: VerifyDetails, name: string): ToolResult<VerifyDetails> {
  const text = details.match
    ? `MATCH: ${name} digest equals the expected value\n${details.digest}`
    : `MISMATCH: ${name} digest differs\nexpected ${shown(details.expected)}\nactual   ${details.digest}`;
  return { content: [{ type: "text", text }], details };
}

/**
 * Checks a secret length against the tool limit.
 *
 * @param name - The argument, for the error.
 * @param value - The value as passed.
 * @returns {number} The length.
 */
function secretLengthArgument(name: string, value: unknown): number {
  if (typeof value !== "number" || !Number.isInteger(value)) {
    throw new InvalidOptionError(name, value, "must be a whole number");
  }
  if (value < 0 || value > MAX_SECRET_LENGTH) {
    throw new InvalidOptionError(name, value, `must be 0 to ${MAX_SECRET_LENGTH} in a tool call`);
  }
  return value;
}

/**
 * Forges a digest per secret length, the message in hex since its padding is binary.
 *
 * @param params - Algorithm, known digest, message, suffix with their encodings, secret lengths.
 * @returns {ToolResult<ExtendDetails>} One forged message per secret length.
 */
export function hashDigestExtend(params: HashDigestExtendParams): ToolResult<ExtendDetails> {
  assertArguments("hashes_digest_extend", params);
  const hex = textArgument("digest", params.digest, MAX_EXPECTED_LENGTH).trim();
  if (!digestPattern.test(hex)) {
    throw new InvalidOptionError(
      "digest",
      hex,
      "must be 16 to 64 bytes in hex, without a 0x prefix",
    );
  }
  const message = toBytes(
    decodedArgument(
      "message",
      textArgument("message", params.message, MAX_INPUT_LENGTH),
      "messageEncoding",
      params.messageEncoding,
    ),
  );
  const suffix = toBytes(
    decodedArgument(
      "suffix",
      textArgument("suffix", params.suffix, MAX_INPUT_LENGTH),
      "suffixEncoding",
      params.suffixEncoding,
    ),
  );
  const first = secretLengthArgument("secretLength", params.secretLength);
  const last =
    params.secretLengthMax === undefined
      ? undefined
      : secretLengthArgument("secretLengthMax", params.secretLengthMax);
  const lengths = secretLengths(first, last, MAX_SECRET_LENGTHS);
  const algorithm = textArgument("algorithm", params.algorithm, MAX_ALGORITHM_LENGTH);
  const digest = Uint8Array.fromHex(hex);
  const extensions: Extension[] = [];
  let forgedLength = 0;
  for (const secretLength of lengths) {
    const forged = extendDigest({ algorithm, digest, message, secretLength, suffix });
    forgedLength += forged.message.length * 2;
    if (forgedLength > MAX_FORGED_LENGTH) {
      throw new InvalidOptionError(
        lengths.length > 1 ? "secretLengthMax" : "message",
        lengths.length > 1 ? lengths.at(-1) : `${message.length} bytes`,
        `the forged messages run past ${MAX_FORGED_LENGTH} hex digits in a tool call. Try fewer lengths, or a shorter message or suffix`,
      );
    }
    extensions.push({
      secretLength,
      digest: forged.digest.toHex(),
      message: forged.message.toHex(),
      padding: forged.padding.toHex(),
    });
  }
  const name = resolveAlgorithm(algorithm).name();
  const blocks = extensions.map((extension) =>
    [
      `${name}, secret of ${extension.secretLength} bytes`,
      `digest  ${extension.digest}`,
      `message ${extension.message}`,
      `padding ${extension.padding}`,
    ].join("\n"),
  );
  const text = [
    "Send message (the original, the padding, the suffix) with digest. The server prepends the secret.",
    ...blocks,
  ].join("\n\n");
  return { content: [{ type: "text", text }], details: { algorithm: name, extensions } };
}

/**
 * Lists the algorithms a hash may come from, with the next call for each one this package computes.
 *
 * A list gets a block per hash and the next step once.
 *
 * @param params - The hash as found, or a list of them.
 * @returns {ToolResult<DigestIdentity | IdentifyBatchDetails>} How it was read and the candidates,
 *   most likely first, or that for every hash of the list.
 */
export function hashDigestIdentify(
  params: HashDigestIdentifyParams & { readonly digest: string },
): ToolResult<DigestIdentity>;
export function hashDigestIdentify(
  params: HashDigestIdentifyParams,
): ToolResult<DigestIdentity | IdentifyBatchDetails>;
export function hashDigestIdentify(
  params: HashDigestIdentifyParams,
): ToolResult<DigestIdentity | IdentifyBatchDetails> {
  assertArguments("hashes_digest_identify", params);
  if (!Array.isArray(params.digest)) {
    const found = identifyDigest(textArgument("digest", params.digest, MAX_EXPECTED_LENGTH));
    const { text, next } = identityBlock(found);
    return { content: [{ type: "text", text: [text, ...next].join("\n") }], details: found };
  }
  const digests =
    listArgument("digest", params.digest, MAX_BATCH_DIGESTS, MAX_EXPECTED_LENGTH) ?? [];
  const blank = digests.findIndex((digest) => digest.trim() === "");
  if (blank !== -1)
    throw new InvalidOptionError(`digest ${blank + 1}`, "(empty)", "must not be empty");
  const items = identifyDigest(digests);
  const blocks = items.map((found, index) => ({
    ...identityBlock(found),
    digest: digests[index] ?? "",
  }));
  const next = [...new Set(blocks.flatMap((block) => block.next))];
  const text = [
    ...blocks.map((block) => `${quoted(block.digest.trim())}\n${block.text}`),
    ...(next.length > 0 ? [next.join("\n")] : []),
  ].join("\n\n");
  return { content: [{ type: "text", text }], details: { items } };
}

/**
 * The lines about one hash, and the next step when a candidate can be checked.
 *
 * @param found - The identity.
 * @returns {{ text: string; next: string[] }} The heading, candidates and limits, then the step.
 */
function identityBlock(found: DigestIdentity): { text: string; next: string[] } {
  const { heading, lines } = identityText(found);
  const refusals = found.candidates.map((candidate) =>
    candidate.algorithm === undefined
      ? undefined
      : toolRefusal(candidate.algorithm, candidate.salt, candidate.parameters),
  );
  const over = found.candidates.flatMap((candidate, index) => {
    const reason = refusals[index];
    return reason === undefined
      ? []
      : [`${candidate.name} is past what hashes_verify runs: ${reason}.`];
  });
  const callable = found.candidates.some(
    (candidate, index) => candidate.algorithm !== undefined && refusals[index] === undefined,
  );
  const next = callable
    ? [
        found.reading === "format"
          ? "Next: hashes_verify a guessed input with that algorithm, salt, parameters and expected."
          : "Next: hashes_verify a known input with each computable candidate. Only a MATCH settles it.",
      ]
    : [];
  return { text: [heading, ...lines, ...over].join("\n"), next };
}

/**
 * Checks a list argument: an array of at most `maxItems` strings, each within its length.
 *
 * @param name - The argument, for the error.
 * @param value - The value as passed.
 * @param maxItems - Most entries.
 * @param maxLength - Longest entry.
 * @returns {string[] | undefined} The entries, or nothing when the argument was left out.
 */
function listArgument(
  name: string,
  value: unknown,
  maxItems: number,
  maxLength: number,
): string[] | undefined {
  if (value === undefined) return undefined;
  if (!Array.isArray(value)) throw new InvalidOptionError(name, value, "must be a list of strings");
  if (value.length === 0 || value.length > maxItems) {
    throw new InvalidOptionError(name, `${value.length} entries`, `takes 1 to ${maxItems}`);
  }
  return value.map((entry: unknown) => textArgument(name, entry, maxLength));
}

/**
 * Checks an optional whole number argument against its tool bounds.
 *
 * @param name - The argument, for the error.
 * @param value - The value as passed.
 * @param maximum - Largest value.
 * @returns {number | undefined} The value, or nothing when it was left out.
 */
function countArgument(name: string, value: unknown, maximum: number): number | undefined {
  if (value === undefined) return undefined;
  if (typeof value !== "number" || !Number.isInteger(value) || value < 1 || value > maximum) {
    throw new InvalidOptionError(name, value, `must be a whole number from 1 to ${maximum}`);
  }
  return value;
}

/**
 * Reads the digest argument of a search: one digest, or a list of up to `MAX_BATCH_DIGESTS`.
 *
 * @param digest - The argument as passed.
 * @param encoding - How the digests are written.
 * @returns {Uint8Array | Uint8Array[]} The bytes, a list for a list.
 */
function searchTargets(
  digest: HashDigestSearchParams["digest"],
  encoding: HashResult["encoding"],
): Uint8Array | Uint8Array[] {
  if (!Array.isArray(digest)) {
    const one = textArgument("digest", digest, MAX_EXPECTED_LENGTH).trim();
    return assertExpected(one, encoding, "digest");
  }
  const digests = listArgument("digest", digest, MAX_BATCH_DIGESTS, MAX_EXPECTED_LENGTH) ?? [];
  return digests.map((each, index) => assertExpected(each.trim(), encoding, `digest ${index + 1}`));
}

/**
 * Searches for the transform of the words behind a digest, or each of a list in one pass, stopping
 * at `MAX_SEARCH_HASHES` or `MAX_SEARCH_BYTES` hashed, since a long text costs more to hash.
 *
 * @param params - The digest or digests and their encoding, the words, and what to try with them.
 * @param onProgress - Hears the running count, as `searchDigest` reports it.
 * @returns {ToolResult<DigestSearch | DigestSearchBatch>} The recipe on a match, or what the
 * search covered, one block per digest for a list.
 */
export function hashDigestSearch(
  params: HashDigestSearchParams & { readonly digest: string },
  onProgress?: SearchDigestOptions["onProgress"],
): ToolResult<DigestSearch>;
export function hashDigestSearch(
  params: HashDigestSearchParams,
  onProgress?: SearchDigestOptions["onProgress"],
): ToolResult<DigestSearch | DigestSearchBatch>;
export function hashDigestSearch(
  params: HashDigestSearchParams,
  onProgress?: SearchDigestOptions["onProgress"],
): ToolResult<DigestSearch | DigestSearchBatch> {
  assertArguments("hashes_digest_search", params);
  const target = searchTargets(params.digest, encodingArgument(params.encoding));
  const words = listArgument("words", params.words, MAX_SEARCH_WORDS, MAX_WORD_LENGTH);
  if (words === undefined) throw new MissingOptionError("words");
  const options: SearchDigestOptions = {
    words,
    minWords: countArgument("minWords", params.minWords, MAX_SEARCH_WORDS),
    maxWords: countArgument("maxWords", params.maxWords, MAX_SEARCH_WORDS),
    joiners: listArgument("joiners", params.joiners, MAX_SEARCH_JOINERS, MAX_JOINER_LENGTH),
    cases: listArgument("cases", params.cases, SEARCH_CASES.length, MAX_ALGORITHM_LENGTH) as
      | SearchCase[]
      | undefined,
    algorithms: listArgument(
      "algorithms",
      params.algorithms,
      MAX_SEARCH_ALGORITHMS,
      MAX_ALGORITHM_LENGTH,
    ),
    rounds: countArgument("rounds", params.rounds, MAX_SEARCH_ROUNDS),
    chains: listArgument("chains", params.chains, SEARCH_CHAINS.length, MAX_ALGORITHM_LENGTH) as
      | SearchChain[]
      | undefined,
    limit: MAX_SEARCH_HASHES,
    byteLimit: MAX_SEARCH_BYTES,
    onProgress,
  };
  const found = Array.isArray(target)
    ? searchDigest(target, options)
    : searchDigest(target, options);
  const { heading, lines } = searchText(found);
  const next = found.stopped
    ? [
        `The tool stops at ${MAX_SEARCH_HASHES} hashes or ${MAX_SEARCH_BYTES} bytes hashed. Narrow words, minWords, maxWords, joiners, cases, algorithms or rounds, or run hashes search from the CLI, which takes --limit.`,
      ]
    : [];
  const text = [...heading, ...lines, ...next].join("\n");
  return { content: [{ type: "text", text }], details: found };
}

/**
 * Says why `hashes_verify` would refuse a call that identify read out of a string.
 *
 * @param name - The algorithm.
 * @param salt - The salt in hex.
 * @param parameters - The costs.
 * @returns {string | undefined} The tool limit it breaks, or nothing.
 */
function toolRefusal(
  name: string,
  salt: string | undefined,
  parameters: Readonly<Record<string, number | string>> | undefined,
): string | undefined {
  try {
    algorithmOptions(resolveAlgorithm(name), salt, parameters);
    return undefined;
  } catch (error) {
    if (error instanceof InvalidOptionError) return error.message;
    throw error;
  }
}

/**
 * Formats one algorithm for the listing.
 *
 * @param info - The algorithm's metadata.
 * @returns {string} Name, family, category, digest size, HMAC support and label.
 */
function listingLine(info: AlgorithmInfo): string {
  const digest = info.digestLength === undefined ? "variable" : `${info.digestLength * 8}-bit`;
  return `${info.name} [${info.family}, ${info.category}] ${digest}, HMAC ${info.hmac ? "yes" : "no"}: ${info.label}`;
}

/**
 * Describes one algorithm with its options, the encoding and key as the tools take them.
 *
 * @param info - The algorithm's metadata.
 * @returns {string} The description.
 */
function infoText(info: AlgorithmInfo): string {
  const lines = [listingLine(info), info.description];
  if (info.securityNote) lines.push(`Security: ${info.securityNote}`);
  const toolDescriptions: Readonly<Record<string, string>> = {
    encoding: `Output encoding: ${TEXT_ENCODINGS.join(", ")}`,
    key: "HMAC key; pass it to hashes_hmac_compute",
  };
  lines.push("Options:");
  for (const option of info.options) {
    const requirement = option.required
      ? "required"
      : `default ${String(option.default ?? "none")}`;
    const description = toolDescriptions[option.name] ?? option.description;
    const choices = option.choices ? `; one of ${option.choices.join(", ")}` : "";
    lines.push(`  ${option.name} (${option.type}, ${requirement}): ${description}${choices}`);
  }
  return lines.join("\n");
}

/**
 * Lists the registered algorithms, optionally one category or family, or describes one algorithm.
 *
 * @param params - Category and family to keep, or an algorithm to describe.
 * @returns {ToolResult<AlgorithmsDetails>} The listing or the description.
 */
export function hashAlgorithms(
  params: Readonly<HashAlgorithmsParams>,
): ToolResult<AlgorithmsDetails> {
  assertArguments("hashes_algorithms", params);
  if (params.algorithm !== undefined) {
    const info = algorithmArgument(params.algorithm).info();
    return { content: [{ type: "text", text: infoText(info) }], details: { algorithms: [info] } };
  }
  const family =
    params.family === undefined
      ? undefined
      : textArgument("family", params.family, MAX_FAMILY_LENGTH);
  const infos = algorithmInfos({ category: params.category, family });
  const lines = [
    `${infos.length} algorithms, listing order:`,
    ...infos.map(listingLine),
    "",
    "Call hashes_algorithms with an algorithm name to see its options.",
  ];
  return { content: [{ type: "text", text: lines.join("\n") }], details: { algorithms: infos } };
}
