import type { HashAlgorithm, HashAlgorithmFactory } from './types'
import { UnknownAlgorithmError } from './errors'

const factories = new Map<string, HashAlgorithmFactory>()
const instances = new Map<string, HashAlgorithm>()

/** Register a hash algorithm factory. */
export function register(name: string, factory: HashAlgorithmFactory): void {
  factories.set(name, factory)
  instances.delete(name) // invalidate cached instance on re-register
}

/** Create a hash algorithm instance by name (cached singleton). */
export function create(name: string): HashAlgorithm {
  const cached = instances.get(name)
  if (cached) return cached
  const factory = factories.get(name)
  if (!factory) throw new UnknownAlgorithmError(name)
  const algorithm = factory()
  instances.set(name, algorithm)
  return algorithm
}

/** List all registered algorithm names. */
export function algorithms(): string[] {
  return [...factories.keys()]
}

/** Check if an algorithm is registered. */
export function has(name: string): boolean {
  return factories.has(name)
}
