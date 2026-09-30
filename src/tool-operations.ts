/**
 * Tool executors shared by the MCP server, the AI SDK tools and the Pi and OMP extensions.
 *
 * Each executor returns the text a caller reads plus the structured details the agent harnesses
 * attach to the call. An MCP client sees only the text, so every fact needed for a follow-up call
 * (the salt a KDF drew, its cost parameters) has to be in it. Every bound the schemas declare is
 * enforced here again, because a host is free to skip schema validation.
 */

import type { Static } from "typebox";
import { decodeInput, parameterText, takesSalt } from "./core/digest.ts";
import { shown } from "./core/errors.ts";
import { checkedParameters, parameterOptions, type ParameterValue } from "./core/options.ts";
import { algorithmInfos } from "./core/resolve.ts";
import { assertExpected } from "./core/verify.ts";
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
  INPUT_ENCODINGS,
  MAX_ALGORITHM_LENGTH,
  MAX_EXPECTED_LENGTH,
  MAX_FAMILY_LENGTH,
  MAX_INPUT_LENGTH,
  MAX_KEY_LENGTH,
  MAX_PARAMETER_LENGTH,
  MAX_PARAMETERS,
  MAX_SCRYPT_MEMORY,
  PARAMETER_LIMITS,
  PARAMETER_NAME_PATTERN,
  SALT_PATTERN,
  TEXT_ENCODINGS,
} from "../packages/shared/tool-contract.ts";
import type { toolSchemas } from "../packages/shared/tool-schemas.ts";

export * from "../packages/shared/tool-contract.ts";

/** Text for the model plus details for the harness, shared by every tool surface. */
export interface ToolResult<Details> {
  content: Array<{ type: "text"; text: string }>;
  details: Details;
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
  hashes_algorithms: ["category", "family", "algorithm"],
};

/** A tool's arguments as its schema declares them, read-only down to nested objects. */
type ReadonlyValue<V> = V extends object ? Readonly<V> : V;
type Arguments<T> = { readonly [K in keyof T]: ReadonlyValue<T[K]> };

export type HashComputeParams = Arguments<Static<typeof toolSchemas.hashes_compute>>;
export type HashHmacParams = Arguments<Static<typeof toolSchemas.hashes_hmac_compute>>;
export type HashVerifyParams = Arguments<Static<typeof toolSchemas.hashes_verify>>;
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

export interface AlgorithmsDetails {
  algorithms: AlgorithmInfo[];
}

const saltPattern = new RegExp(SALT_PATTERN);
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
 * Checks what the schema declares about `parameters` again: how many, the names, the length of
 * a text value, and that the salt comes through its own bounded argument.
 *
 * @param given - The parameters as passed.
 */
function assertParameterEntries(given: Readonly<Record<string, unknown>>): void {
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
    if (name === "salt") {
      throw new InvalidOptionError("parameters", name, "pass the salt as the salt argument");
    }
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
  if (limit !== undefined && typeof value === "number" && (value < 1 || value > limit)) {
    throw new InvalidOptionError(name, value, `must be 1 to ${limit} in a tool call`);
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
  assertParameterEntries(given);
  const hexSalt = saltArgument(salt);
  if (hexSalt !== undefined) given["salt"] = hexSalt;
  const options = checkedParameters(algorithm, given);
  for (const [name, value] of Object.entries(options)) assertWithinLimit(name, value);
  assertScryptMemory(algorithm, options);
  return options;
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
  const defaults = Object.fromEntries(
    parameterOptions(algorithm).map((option) => [option.name, option.default]),
  );
  if (!("N" in defaults && "r" in defaults && "p" in defaults)) return;
  const cost = (name: string): number => Number(options[name] ?? defaults[name]);
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
  const parameters = parameterText(details.options);
  const label = details.operation === "hmac" ? `HMAC-${details.algorithm}` : details.algorithm;
  const about = `${label}, ${details.encoding}, ${details.digestLength} bytes`;
  return `${details.digest}\n${parameters ? `${about}, ${parameters}` : about}`;
}

/**
 * Hashes text with any registered algorithm. A KDF without a salt draws a random one and the
 * answer names it, since the digest cannot be reproduced without it.
 *
 * @param params - Algorithm, input and its encoding, digest encoding and, for a KDF, the salt in hex.
 * @returns {ToolResult<DigestDetails>} The digest.
 */
export function hashCompute(params: HashComputeParams): ToolResult<DigestDetails> {
  assertArguments("hashes_compute", params);
  const algorithm = algorithmArgument(params.algorithm);
  const input = inputArgument(params.input, params.inputEncoding);
  const encoding = encodingArgument(params.encoding);
  const options = algorithmOptions(algorithm, params.salt, params.parameters);
  const result = algorithm.hash(input, { encoding, ...options } as HashOptions);
  const details = digestDetails(result, encoding);
  return { content: [{ type: "text", text: digestText(details) }], details };
}

/**
 * Computes an HMAC with an algorithm that offers it.
 *
 * @param params - Algorithm, input and its encoding, key and its encoding, digest encoding.
 * @returns {ToolResult<DigestDetails>} The HMAC.
 */
export function hashHmac(params: Readonly<HashHmacParams>): ToolResult<DigestDetails> {
  assertArguments("hashes_hmac_compute", params);
  const algorithm = algorithmArgument(params.algorithm);
  const input = inputArgument(params.input, params.inputEncoding);
  const key = keyArgument(params.key, params.keyEncoding);
  const encoding = encodingArgument(params.encoding);
  if (!algorithm.info().hmac) {
    throw new InvalidOptionError("algorithm", algorithm.name(), "has no HMAC mode");
  }
  const details = digestDetails(algorithm.hash(input, { encoding, key }), encoding);
  return { content: [{ type: "text", text: digestText(details) }], details };
}

/**
 * Hashes the input and compares the digest with an expected one, in constant time. Hex ignores
 * case; base64 and base64url do not. An expected digest that is not valid in its encoding is an
 * error, not a mismatch. A KDF needs the salt the expected digest was made with.
 *
 * @param params - Algorithm, input and its encoding, expected digest and its encoding and, for
 *   a KDF, the salt.
 * @returns {ToolResult<VerifyDetails>} Whether the digests match, with both of them.
 */
export function hashVerify(params: HashVerifyParams): ToolResult<VerifyDetails> {
  assertArguments("hashes_verify", params);
  const algorithm = algorithmArgument(params.algorithm);
  const input = inputArgument(params.input, params.inputEncoding);
  const expected = textArgument("expected", params.expected, MAX_EXPECTED_LENGTH).trim();
  if (expected === "") throw new InvalidOptionError("expected", "", "must not be empty");
  const encoding = encodingArgument(params.encoding);
  assertExpected(expected, encoding);
  const options = algorithmOptions(algorithm, params.salt, params.parameters);
  if (options["salt"] === undefined && takesSalt(algorithm.info())) {
    throw new MissingOptionError("salt (the one the expected digest was made with)");
  }
  const result = algorithm.hash(input, { encoding, ...options } as HashOptions);
  const details = { ...digestDetails(result, encoding), expected };
  const match = digestMatches(result, expected);
  const text = match
    ? `MATCH: ${algorithm.name()} digest equals the expected value\n${details.digest}`
    : `MISMATCH: ${algorithm.name()} digest differs\nexpected ${shown(expected)}\nactual   ${details.digest}`;
  return { content: [{ type: "text", text }], details: { ...details, match } };
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
 * Describes one algorithm with its options.
 *
 * @param info - The algorithm's metadata.
 * @returns {string} The description.
 */
function infoText(info: AlgorithmInfo): string {
  const lines = [listingLine(info), info.description];
  if (info.securityNote) lines.push(`Security: ${info.securityNote}`);
  lines.push("Options:");
  for (const option of info.options) {
    const requirement = option.required
      ? "required"
      : `default ${String(option.default ?? "none")}`;
    lines.push(`  ${option.name} (${option.type}, ${requirement}): ${option.description}`);
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
