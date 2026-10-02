import { readFileSync } from "node:fs";
import { INPUT_ENCODINGS, TEXT_ENCODINGS } from "../../packages/shared/tool-contract.ts";
import { ENCODING_OPTION, decodeInput, parameterText, type InputEncoding } from "../core/digest.ts";
import {
  InvalidOptionError,
  builtinAlgorithms,
  checkedParameters,
  create,
  parameterOptions,
  type Hash,
  type HashInput,
  type HashResult,
  type OutputEncoding,
  type ParameterValue,
} from "../index.ts";

const ENCODINGS: readonly OutputEncoding[] = [...TEXT_ENCODINGS, "binary"];

/** The `--encoding` flag every digest command takes. */
export const encodingArg = {
  type: "string",
  description: ENCODING_OPTION.description,
  alias: "e",
  default: "hex",
} as const;

/** The `--input-encoding` flag of every command that hashes an input. */
export const inputEncodingArg = {
  type: "string",
  description:
    "How to read the input: utf8, or hex and base64 for the bytes they spell (a public key, a raw transaction)",
  default: "utf8",
} as const;

/** The `--key-encoding` flag of `hmac`. */
export const keyEncodingArg = {
  type: "string",
  description: "How to read the key: utf8, or hex and base64 for a binary key (a BIP32 chain code)",
  default: "utf8",
} as const;

/** A string flag citty parses. */
interface StringArg {
  readonly type: "string";
  readonly description: string;
}

/**
 * One flag per option the built-in algorithms take besides encoding and key, such as `--salt`,
 * `--seed`, `--N` or `--iterations`, each naming the algorithms that declare it.
 *
 * @returns {Record<string, StringArg>} The flags by option name.
 */
function builtinParameterArgs(): Record<string, StringArg> {
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
      { type: "string", description: `${flag.description} (${takenBy(flag.algorithms)})` },
    ]),
  );
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

/** The parameter flags of `hash` and `verify`. */
export const parameterArgs = builtinParameterArgs();

/**
 * Reads the parameter flags that were given and checks them against the algorithm, so a flag
 * the algorithm does not take is an error instead of a digest computed without it.
 *
 * @param algorithm - The resolved algorithm.
 * @param args - The parsed arguments.
 * @returns {Record<string, ParameterValue>} The options to hash with.
 */
export function readParameters(
  algorithm: Hash,
  args: Readonly<Record<string, unknown>>,
): Record<string, ParameterValue> {
  const given = Object.fromEntries(
    Object.keys(parameterArgs)
      .filter((name) => args[name] !== undefined)
      .map((name) => [name, args[name]] as const),
  );
  return checkedParameters(algorithm, given);
}

/**
 * Checks the `--encoding` flag.
 *
 * @param value - The flag as given.
 * @returns {OutputEncoding} The encoding.
 */
export function parseEncoding(value: string | undefined): OutputEncoding {
  const encoding = value ?? "hex";
  if ((ENCODINGS as readonly string[]).includes(encoding)) return encoding as OutputEncoding;
  throw new InvalidOptionError("encoding", encoding, `use one of ${ENCODINGS.join(", ")}`);
}

/**
 * Checks an input encoding flag.
 *
 * @param flag - The flag name, for the error.
 * @param value - The flag as given.
 * @returns {InputEncoding} The encoding, `utf8` when omitted.
 */
export function parseInputEncoding(flag: string, value: string | undefined): InputEncoding {
  const encoding = value ?? "utf8";
  if ((INPUT_ENCODINGS as readonly string[]).includes(encoding)) return encoding as InputEncoding;
  throw new InvalidOptionError(flag, encoding, `use one of ${INPUT_ENCODINGS.join(", ")}`);
}

/**
 * Reads the input argument: `-` means stdin, anything else is the input itself. In utf8 it is
 * hashed as given, stdin byte for byte; in hex or base64 it is decoded to the bytes it spells.
 *
 * @param value - The argument as given.
 * @param encoding - The `--input-encoding` flag as given.
 * @returns {HashInput} Text, or bytes.
 */
export function readInput(value: string, encoding: string | undefined): HashInput {
  const inputEncoding = parseInputEncoding("input-encoding", encoding);
  const stdin = value === "-" ? new Uint8Array(readFileSync(0)) : undefined;
  if (inputEncoding === "utf8") return stdin ?? value;
  const text = stdin === undefined ? value : new TextDecoder().decode(stdin);
  return decodeInput(text, inputEncoding);
}

/**
 * Reads the HMAC key argument as the `--key-encoding` flag says.
 *
 * @param value - The key as given.
 * @param encoding - The `--key-encoding` flag as given.
 * @returns {HashInput} Text, or bytes.
 */
export function readKey(value: string, encoding: string | undefined): HashInput {
  return decodeInput(value, parseInputEncoding("key-encoding", encoding), "key");
}

/**
 * Prints a digest on stdout: text with a newline, bytes as they are. A salted digest cannot be
 * reproduced without its salt and cost, so those go to stderr and stdout stays the digest alone.
 *
 * @param result - The computed hash.
 */
export function printDigest(result: HashResult): void {
  if ("salt" in result.options) process.stderr.write(`${parameterText(result.options)}\n`);
  if (typeof result.digest === "string") {
    process.stdout.write(`${result.digest}\n`);
  } else {
    process.stdout.write(result.digest);
  }
}
