import { readFileSync } from "node:fs";
import { TEXT_ENCODINGS } from "../../packages/shared/tool-contract.ts";
import { ENCODING_OPTION, parameterText } from "../core/digest.ts";
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
      { type: "string", description: `${flag.description} (${flag.algorithms.join(", ")})` },
    ]),
  );
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
 * Reads the input argument: `-` means the bytes on stdin, anything else is the text itself.
 *
 * @param value - The argument as given.
 * @returns {HashInput} Text, or the bytes read from stdin.
 */
export function readInput(value: string): HashInput {
  return value === "-" ? new Uint8Array(readFileSync(0)) : value;
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
