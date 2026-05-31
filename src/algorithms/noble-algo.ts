/**
 * Generic factory for @noble/hashes-backed hash algorithms.
 * Each algorithm exports a hash function (data) → Uint8Array and .create() for streaming.
 * HMAC uses @noble/hashes/hmac.
 */
import { hmac } from '@noble/hashes/hmac.js'
import type { CHash } from '@noble/hashes/utils.js'
import type { AlgorithmInfo, HashAlgorithm, HashOptions, HashResult, HashFamily, HashOption } from '../core/types'
import { toBytes, nobleHash, nobleHmac } from './noble-helper'
import { register } from '../core/registry'

interface NobleAlgorithmDef {
  name: string
  label: string
  description: string
  family: HashFamily
  /** The noble CHash (e.g. sha256, blake2b, sha3_256). */
  hashFn: CHash
  digestLength?: number
  hmac?: boolean
  securityNote?: string
  options?: HashOption[]
}

export function makeNobleAlgorithm(def: NobleAlgorithmDef): HashAlgorithm {
  return {
    name(): string { return def.name },
    info(): AlgorithmInfo {
      return {
        name: def.name,
        label: def.label,
        description: def.description,
        family: def.family,
        digestLength: def.digestLength,
        hmac: def.hmac ?? true,
        options: [
          { name: 'encoding', type: 'string', required: false, default: 'hex', description: 'Output encoding: hex, base64, base64url, binary' },
          ...(def.hmac !== false ? [{ name: 'key', type: 'string' as const, required: false, description: 'HMAC key — enables HMAC mode' }] : []),
          ...(def.options ?? []),
        ],
        securityNote: def.securityNote,
      }
    },
    hash(input: string, options?: HashOptions): HashResult {
      const data = toBytes(input)
      if (options?.key) {
        const key = toBytes(options.key as string)
        return nobleHmac(def.name, () => hmac(def.hashFn, key, data), options)
      }
      return nobleHash(def.name, () => def.hashFn(data), options)
    },
  }
}

/** Register a noble-backed algorithm in one call. */
export function registerNobleAlgorithm(def: NobleAlgorithmDef): void {
  register(def.name, () => makeNobleAlgorithm(def))
}
