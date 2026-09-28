/**
 * Tool executors shared by the MCP server, the AI SDK tools and the Pi and OMP extensions.
 *
 * Each executor returns the text a caller reads plus the structured details the agent harnesses
 * attach to the call. An MCP client sees only the text, so every fact needed for a follow-up call
 * (the salt a KDF drew, its cost parameters) has to be in it. Every bound the schemas declare is
 * enforced here again, because a host is free to skip schema validation.
 */

import {
  InvalidOptionError,
  MissingOptionError,
  UnknownAlgorithmError,
  algorithms,
  create,
  digestMatches,
  has,
  hashFamilies,
  normalizeAlgorithmName,
  resolveAlgorithm,
  type AlgorithmInfo,
  type HashAlgorithm,
  type HashResult,
} from "./index.ts";
import {
  MAX_ALGORITHM_LENGTH,
  MAX_EXPECTED_LENGTH,
  MAX_INPUT_LENGTH,
  MAX_KEY_LENGTH,
  SALT_PATTERN,
  TEXT_ENCODINGS,
} from "../packages/shared/tool-contract.ts";

export * from "../packages/shared/tool-contract.ts";

/** Text for the model plus details for the harness, shared by every tool surface. */
export interface ToolResult<Details> {
  content: Array<{ type: "text"; text: string }>;
  details: Details;
}

/** Encodings a tool can return: text only, since a tool answers in text. */
export type TextEncoding = (typeof TEXT_ENCODINGS)[number];

/** The families whose digest depends on a salt. */
const SALTED_FAMILIES = new Set(["password"]);

/** Every argument each tool takes; anything else is rejected, not ignored. */
export const TOOL_ARGUMENTS = {
  hash_compute: ["algorithm", "input", "encoding", "salt"],
  hash_hmac: ["algorithm", "input", "key", "encoding"],
  hash_verify: ["algorithm", "input", "expected", "encoding", "salt"],
  hash_algorithms: ["family", "algorithm"],
} as const;

export type ToolName = keyof typeof TOOL_ARGUMENTS;

export interface HashComputeParams {
  algorithm: string;
  input: string;
  encoding?: TextEncoding;
  salt?: string;
}

export interface HashHmacParams {
  algorithm: string;
  input: string;
  key: string;
  encoding?: TextEncoding;
}

export interface HashVerifyParams {
  algorithm: string;
  input: string;
  expected: string;
  encoding?: TextEncoding;
  salt?: string;
}

export interface HashAlgorithmsParams {
  family?: string;
  algorithm?: string;
}

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

/**
 * Quotes a value the caller sent before it goes into an error message. The host hands that
 * message to the model as it is, so a raw line break in an argument would add a line that reads
 * as the tool's own answer.
 *
 * @param value - The value as passed.
 * @returns {string} The value as JSON.
 */
function echo(value: unknown): string {
  return JSON.stringify(value) ?? String(value);
}

/**
 * Rejects any key the tool does not take. A misspelled optional argument would otherwise be
 * dropped and change the answer without a sign: `salt_hex` would hash with a fresh random salt.
 *
 * @param tool - The tool the arguments are for.
 * @param params - The arguments as the host passed them.
 */
export function assertArguments(tool: ToolName, params: Readonly<object>): void {
  const accepted: readonly string[] = TOOL_ARGUMENTS[tool];
  for (const key of Object.keys(params)) {
    if (!accepted.includes(key)) {
      throw new InvalidOptionError(
        JSON.stringify(key),
        "(unknown)",
        `${tool} takes only ${accepted.join(", ")}`,
      );
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
  throw new InvalidOptionError("encoding", echo(value), `use one of ${TEXT_ENCODINGS.join(", ")}`);
}

/**
 * Checks the optional salt against the algorithm: a KDF takes it, any other algorithm refuses it
 * instead of hashing without it.
 *
 * @param algorithm - The resolved algorithm.
 * @param value - The salt as passed.
 * @returns {string | undefined} The salt in hex, when given.
 */
function saltArgument(algorithm: HashAlgorithm, value: unknown): string | undefined {
  if (value === undefined) return undefined;
  if (typeof value !== "string" || !new RegExp(SALT_PATTERN).test(value)) {
    throw new InvalidOptionError("salt", echo(value), "must be 1 to 256 bytes in hex");
  }
  if (!SALTED_FAMILIES.has(algorithm.info().family)) {
    throw new InvalidOptionError("salt", echo(value), `${algorithm.name()} takes no salt`);
  }
  return value;
}

/**
 * Resolves the algorithm argument.
 *
 * @param value - The name as passed.
 * @returns {HashAlgorithm} The algorithm.
 */
function algorithmArgument(value: unknown): HashAlgorithm {
  const name = textArgument("algorithm", value, MAX_ALGORITHM_LENGTH);
  if (!has(normalizeAlgorithmName(name))) {
    throw new UnknownAlgorithmError(echo(name), algorithms());
  }
  return resolveAlgorithm(name);
}

/**
 * Lists the options a digest depends on besides its encoding, such as a KDF's salt and cost.
 *
 * @param options - The options the result reports.
 * @returns {string} `name value` pairs, or an empty string.
 */
function parameterText(options: Readonly<Record<string, unknown>>): string {
  return Object.entries(options)
    .filter(([name]) => name !== "encoding" && name !== "hmac")
    .map(([name, value]) => `${name} ${String(value)}`)
    .join(", ");
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
 * @param params - Algorithm, input, encoding and, for a KDF, the salt in hex.
 * @returns {ToolResult<DigestDetails>} The digest.
 */
export function hashCompute(params: Readonly<HashComputeParams>): ToolResult<DigestDetails> {
  assertArguments("hash_compute", params);
  const algorithm = algorithmArgument(params.algorithm);
  const input = textArgument("input", params.input, MAX_INPUT_LENGTH);
  const encoding = encodingArgument(params.encoding);
  const salt = saltArgument(algorithm, params.salt);
  const result = algorithm.hash(input, { encoding, ...(salt === undefined ? {} : { salt }) });
  const details = digestDetails(result, encoding);
  return { content: [{ type: "text", text: digestText(details) }], details };
}

/**
 * Computes an HMAC with an algorithm that offers it.
 *
 * @param params - Algorithm, input, key and encoding.
 * @returns {ToolResult<DigestDetails>} The HMAC.
 */
export function hashHmac(params: Readonly<HashHmacParams>): ToolResult<DigestDetails> {
  assertArguments("hash_hmac", params);
  const algorithm = algorithmArgument(params.algorithm);
  const input = textArgument("input", params.input, MAX_INPUT_LENGTH);
  const key = textArgument("key", params.key, MAX_KEY_LENGTH);
  const encoding = encodingArgument(params.encoding);
  if (!algorithm.info().hmac) {
    throw new InvalidOptionError("algorithm", algorithm.name(), "has no HMAC mode");
  }
  const details = digestDetails(algorithm.hash(input, { encoding, key }), encoding);
  return { content: [{ type: "text", text: digestText(details) }], details };
}

/**
 * Hashes the input and compares the digest with an expected one, in constant time. Hex ignores
 * case; base64 and base64url do not. A KDF needs the salt the expected digest was made with.
 *
 * @param params - Algorithm, input, expected digest, its encoding and, for a KDF, the salt.
 * @returns {ToolResult<VerifyDetails>} Whether the digests match, with both of them.
 */
export function hashVerify(params: Readonly<HashVerifyParams>): ToolResult<VerifyDetails> {
  assertArguments("hash_verify", params);
  const algorithm = algorithmArgument(params.algorithm);
  const input = textArgument("input", params.input, MAX_INPUT_LENGTH);
  const expected = textArgument("expected", params.expected, MAX_EXPECTED_LENGTH).trim();
  const encoding = encodingArgument(params.encoding);
  const salt = saltArgument(algorithm, params.salt);
  if (salt === undefined && SALTED_FAMILIES.has(algorithm.info().family)) {
    throw new MissingOptionError("salt (the one the expected digest was made with)");
  }
  const result = algorithm.hash(input, { encoding, ...(salt === undefined ? {} : { salt }) });
  const details = { ...digestDetails(result, encoding), expected };
  const match = digestMatches(result, expected);
  const text = match
    ? `MATCH: ${algorithm.name()} digest equals the expected value\n${details.digest}`
    : `MISMATCH: ${algorithm.name()} digest differs\nexpected ${expected}\nactual   ${details.digest}`;
  return { content: [{ type: "text", text }], details: { ...details, match } };
}

/**
 * Formats one algorithm for the listing.
 *
 * @param info - The algorithm's metadata.
 * @returns {string} Name, family, digest size, HMAC support and label.
 */
function listingLine(info: AlgorithmInfo): string {
  const digest = info.digestLength === undefined ? "variable" : `${info.digestLength * 8}-bit`;
  return `${info.name} [${info.family}] ${digest}, HMAC ${info.hmac ? "yes" : "no"}: ${info.label}`;
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
 * Lists the registered algorithms, optionally one family, or describes one algorithm.
 *
 * @param params - Family to keep, or an algorithm to describe.
 * @returns {ToolResult<AlgorithmsDetails>} The listing or the description.
 */
export function hashAlgorithms(
  params: Readonly<HashAlgorithmsParams>,
): ToolResult<AlgorithmsDetails> {
  assertArguments("hash_algorithms", params);
  if (params.algorithm !== undefined) {
    const info = algorithmArgument(params.algorithm).info();
    return { content: [{ type: "text", text: infoText(info) }], details: { algorithms: [info] } };
  }
  const family = params.family;
  if (family !== undefined && !(hashFamilies as readonly string[]).includes(family)) {
    throw new InvalidOptionError("family", echo(family), `use one of ${hashFamilies.join(", ")}`);
  }
  const infos = algorithms()
    .map((name) => create(name).info())
    .filter((info) => family === undefined || info.family === family);
  const lines = [
    `${infos.length} algorithms, listing order:`,
    ...infos.map(listingLine),
    "",
    "Call hash_algorithms with an algorithm name to see its options.",
  ];
  return { content: [{ type: "text", text: lines.join("\n") }], details: { algorithms: infos } };
}
