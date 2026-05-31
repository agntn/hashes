/** Base error for hashhouse. */
export class HashError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'HashError'
  }
}

/** Algorithm not found in registry. */
export class UnknownAlgorithmError extends HashError {
  constructor(public readonly algorithm: string) {
    super(`Unknown algorithm: ${algorithm}`)
    this.name = 'UnknownAlgorithmError'
  }
}

/** Invalid option value. */
export class InvalidOptionError extends HashError {
  constructor(
    public readonly option: string,
    public readonly value: unknown,
    public readonly reason: string,
  ) {
    super(`Invalid option ${option}=${value}: ${reason}`)
    this.name = 'InvalidOptionError'
  }
}

/** Missing required option. */
export class MissingOptionError extends HashError {
  constructor(public readonly option: string) {
    super(`Missing required option: ${option}`)
    this.name = 'MissingOptionError'
  }
}

/** Algorithm dependency not installed. */
export class DependencyError extends HashError {
  constructor(
    public readonly algorithm: string,
    public readonly dependency: string,
  ) {
    super(`Algorithm "${algorithm}" requires "${dependency}" — install it first`)
    this.name = 'DependencyError'
  }
}

/** Normalizes any thrown value into a HashError. */
export function normalizeError(error: unknown, algorithm?: string): HashError {
  if (error instanceof HashError) return error
  const msg = error instanceof Error ? error.message : String(error)
  return new HashError(algorithm ? `[${algorithm}] ${msg}` : msg)
}
