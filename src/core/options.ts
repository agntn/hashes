import { InvalidOptionError } from "./errors.ts";
import type { Hash } from "./hash.ts";
import type { HashOption } from "./types.ts";

/** Options a surface passes itself, never as a parameter: the output encoding and the HMAC key. */
const RESERVED = new Set(["encoding", "key"]);

/** A parameter value as a caller passes it: an integer or a string. */
export type ParameterValue = number | string;

/**
 * The options an algorithm takes as parameters, such as a KDF's salt and cost or xxHash's seed.
 *
 * @param algorithm - The algorithm.
 * @returns {HashOption[]} Its declared options without `encoding` and `key`.
 */
export function parameterOptions(algorithm: Hash): HashOption[] {
  return algorithm.info().options.filter((option) => !RESERVED.has(option.name));
}

/**
 * Reads one value by the option's declared type. A number may come as digits in a string, as it
 * does from a command line.
 *
 * @param option - The declared option.
 * @param value - The value as passed.
 * @returns {ParameterValue} The value in the option's type.
 */
function coerce(option: Readonly<HashOption>, value: unknown): ParameterValue {
  if (option.type !== "number") {
    if (typeof value !== "string")
      throw new InvalidOptionError(option.name, value, "must be a string");
    return value;
  }
  const number = typeof value === "string" && /^-?\d+$/.test(value.trim()) ? Number(value) : value;
  if (typeof number !== "number" || !Number.isSafeInteger(number)) {
    throw new InvalidOptionError(option.name, value, "must be an integer");
  }
  return number;
}

/**
 * Checks parameters against the options the algorithm declares. A name the algorithm does not
 * declare is an error, never dropped: `--salt` on sha256 would otherwise hash without it.
 *
 * @param algorithm - The algorithm the parameters are for.
 * @param values - Parameter values by option name.
 * @returns {Record<string, ParameterValue>} The values in their declared types.
 */
export function checkedParameters(
  algorithm: Hash,
  values: Readonly<Record<string, unknown>>,
): Record<string, ParameterValue> {
  const declared = new Map(
    parameterOptions(algorithm).map((option) => [option.name, option] as const),
  );
  const checked: Record<string, ParameterValue> = {};
  for (const [name, value] of Object.entries(values)) {
    const option = declared.get(name);
    if (option === undefined) {
      const takes =
        declared.size > 0 ? `takes ${[...declared.keys()].join(", ")}` : "takes no parameters";
      throw new InvalidOptionError(name, value, `${algorithm.name()} ${takes}`);
    }
    checked[name] = coerce(option, value);
  }
  return checked;
}
