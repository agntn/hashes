const CONTROL = /\p{Cc}/u;

/**
 * Shows a caller's value inside an error message. A value with a line break or another control
 * character is written as JSON: these messages reach a model as they are, and a raw line break
 * would add a line that reads as the tool's own answer. The error's fields keep the raw value.
 *
 * @param value - The value as the caller passed it.
 * @returns {string} The value as it appears in the message.
 */
function shown(value: unknown): string {
  const text = String(value);
  return CONTROL.test(text) ? JSON.stringify(text) : text;
}

/** Base error for @agntn/hashes. */
export class HashError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "HashError";
  }
}

/** Algorithm not found in the registry. */
export class UnknownAlgorithmError extends HashError {
  readonly algorithm: string;
  /** Names that were registered when the lookup failed. */
  readonly available: readonly string[];

  constructor(algorithm: string, available: readonly string[] = []) {
    super(
      available.length > 0
        ? `Unknown algorithm: ${shown(algorithm)}. Available: ${available.join(", ")}`
        : `Unknown algorithm: ${shown(algorithm)}`,
    );
    this.name = "UnknownAlgorithmError";
    this.algorithm = algorithm;
    this.available = available;
  }
}

/** Invalid option value. */
export class InvalidOptionError extends HashError {
  readonly option: string;
  readonly value: unknown;
  readonly reason: string;

  constructor(option: string, value: unknown, reason: string) {
    super(`Invalid option ${shown(option)}=${shown(value)}: ${reason}`);
    this.name = "InvalidOptionError";
    this.option = option;
    this.value = value;
    this.reason = reason;
  }
}

/** Missing required option. */
export class MissingOptionError extends HashError {
  readonly option: string;

  constructor(option: string) {
    super(`Missing required option: ${option}`);
    this.name = "MissingOptionError";
    this.option = option;
  }
}

/** Algorithm dependency not installed. */
export class DependencyError extends HashError {
  readonly algorithm: string;
  readonly dependency: string;

  constructor(algorithm: string, dependency: string) {
    super(`Algorithm "${algorithm}" requires "${dependency}"; install it first`);
    this.name = "DependencyError";
    this.algorithm = algorithm;
    this.dependency = dependency;
  }
}

/**
 * Normalizes any thrown value into a HashError.
 *
 * @param error - The thrown value.
 * @param algorithm - Algorithm the failure belongs to, prefixed to a foreign message.
 * @returns {HashError} The same error when it already is one, otherwise a wrapped copy.
 */
export function normalizeError(error: unknown, algorithm?: string): HashError {
  if (error instanceof HashError) return error;
  const message = error instanceof Error ? error.message : String(error);
  return new HashError(algorithm ? `[${algorithm}] ${message}` : message);
}
