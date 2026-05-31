import type { HashAlgorithm } from './types'
import { algorithms, has, create } from './registry'

/** Resolve a hash algorithm by exact name. */
export function resolveAlgorithm(preferred?: string): HashAlgorithm {
  if (preferred) {
    const normalized = preferred.toLowerCase().replace(/\s+/g, '-').replace(/_/g, '-')
    if (has(normalized)) return create(normalized)
  }
  const available = algorithms()
  throw new Error(
    `Unknown algorithm: ${preferred ?? '(none)'}\nAvailable: ${available.join(', ')}`,
  )
}
