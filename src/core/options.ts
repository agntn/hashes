import { assertOneRound } from "./digest.ts";
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

/** Options only a plain digest takes: `ROUND_OPTIONS` and SHA-256's `bitLength`, never HMAC. */
const DIGEST_ONLY = new Set(["rounds", "chain", "bitLength"]);

/**
 * What an HMAC or a length extension can use: every parameter but `rounds`, `chain`, `bitLength`.
 *
 * @param algorithm - The algorithm.
 * @returns {HashOption[]} HAVAL's passes and bits, say, or nothing at all for SHA-256.
 */
export function oneRoundOptions(algorithm: Hash): HashOption[] {
  return parameterOptions(algorithm).filter((option) => !DIGEST_ONLY.has(option.name));
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
  const coerced = coerceType(option, value);
  if (option.choices && !option.choices.includes(coerced)) {
    throw new InvalidOptionError(option.name, value, `use one of ${option.choices.join(", ")}`);
  }
  return coerced;
}

/**
 * Reads one value by the option's declared type, before its choices are checked.
 *
 * @param option - The declared option.
 * @param value - The value as passed.
 * @returns {ParameterValue} The value in the option's type.
 */
function coerceType(option: Readonly<HashOption>, value: unknown): ParameterValue {
  if (option.type !== "number") {
    if (typeof value !== "string")
      throw new InvalidOptionError(option.name, value, "must be a string");
    return value;
  }
  if (typeof value === "string" && /^-?\d+$/.test(value.trim())) {
    // Past 2^53 a double loses digits; the exact text goes on for the algorithm to read.
    const number = Number(value);
    return Number.isSafeInteger(number) ? number : value.trim();
  }
  if (typeof value !== "number" || !Number.isSafeInteger(value)) {
    throw new InvalidOptionError(
      option.name,
      value,
      "must be an integer; pass one past 2^53 as text",
    );
  }
  return value;
}

/**
 * Checks parameters against the options the algorithm declares. A name the algorithm does not
 * declare is an error, never dropped: `--salt` on sha256 would otherwise hash without it.
 *
 * @param algorithm - The algorithm the parameters are for.
 * @param values - Parameter values by option name.
 * @param oneRound - Why the call runs one round, as HMAC and extension do: a second round gets it
 *   as its error, and an unknown name hears only what `oneRoundOptions` lists.
 * @returns {Record<string, ParameterValue>} The values in their declared types.
 */
export function checkedParameters(
  algorithm: Hash,
  values: Readonly<Record<string, unknown>>,
  oneRound?: string,
): Record<string, ParameterValue> {
  const declared = new Map(
    parameterOptions(algorithm).map((option) => [option.name, option] as const),
  );
  const checked: Record<string, ParameterValue> = {};
  for (const [name, value] of Object.entries(values)) {
    const option = declared.get(name);
    if (option === undefined) throw unknownParameter(algorithm, name, value, oneRound);
    checked[name] = coerce(option, value);
  }
  if (oneRound !== undefined) assertOneRound(checked, oneRound);
  return checked;
}

/**
 * Refuses a name the algorithm doesn't declare, and names what the call does take instead.
 *
 * @param algorithm - The algorithm the parameter was for.
 * @param name - The parameter as passed.
 * @param value - Its value.
 * @param oneRound - Why the call runs one round, when it does: `rounds` and `chain` stay unlisted.
 * @returns {InvalidOptionError} The error to throw.
 */
function unknownParameter(
  algorithm: Hash,
  name: string,
  value: unknown,
  oneRound: string | undefined,
): InvalidOptionError {
  const taken = (oneRound === undefined ? parameterOptions : oneRoundOptions)(algorithm);
  const takes =
    taken.length > 0
      ? `takes ${taken.map((option) => option.name).join(", ")}`
      : "takes no parameters";
  return new InvalidOptionError(name, value, `${algorithm.name()} ${takes}`);
}
