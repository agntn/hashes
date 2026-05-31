import type { BinaryLike } from 'node:crypto'
import type { HashAlgorithm, AlgorithmInfo, HashOptions, HashResult, OutputEncoding } from '../core/types'
import { normalizeError } from '../core/errors'
import { register } from '../core/registry'

/** FNV-1a 64-bit parameters. */
const FNV64_OFFSET = 0xcbf29ce484222325n
const FNV64_PRIME = 0x100000001b3n
const MASK64 = 0xFFFFFFFFFFFFFFFFn

function fnv1a64(data: Uint8Array): bigint {
  let hash = FNV64_OFFSET
  for (let i = 0; i < data.length; i++) {
    hash = (hash ^ BigInt(data[i]!)) & MASK64
    hash = (hash * FNV64_PRIME) & MASK64
  }
  return hash
}

function toBytes(input: string | Uint8Array): Uint8Array {
  return typeof input === 'string' ? new TextEncoder().encode(input) : input
}

class Fnv1aAlgorithm implements HashAlgorithm {
  name(): string { return 'fnv1a' }

  info(): AlgorithmInfo {
    return {
      name: 'fnv1a',
      label: 'FNV-1a (64-bit)',
      description: 'FNV-1a 64-bit — simple, fast non-cryptographic hash used in hash tables and dedup',
      family: 'non-cryptographic',
      digestLength: 8,
      hmac: false,
      options: [
        { name: 'encoding', type: 'string', required: false, default: 'hex', description: 'Output encoding: hex, base64, base64url, binary' },
      ],
      securityNote: 'NOT for security — simple hash for hash tables, fingerprints, dedup',
    }
  }

  hash(input: BinaryLike | string, options?: HashOptions): HashResult {
    try {
      const encoding: OutputEncoding = options?.encoding ?? 'hex'
      const bytes = toBytes(input as string | Uint8Array)
      const hash = fnv1a64(bytes)
      const raw = Buffer.alloc(8)
      raw.writeBigUInt64BE(hash)

      if (encoding === 'binary') {
        return {
          digest: new Uint8Array(raw),
          algorithm: 'fnv1a',
          operation: 'hash',
          encoding,
          digestLength: 8,
          options: { encoding },
        }
      }

      const outEncoding = encoding === 'base64url' ? 'base64url' : encoding
      return {
        digest: raw.toString(outEncoding as 'hex' | 'base64' | 'base64url'),
        algorithm: 'fnv1a',
        operation: 'hash',
        encoding,
        digestLength: 8,
        options: { encoding },
      }
    } catch (e) {
      throw normalizeError(e, 'fnv1a')
    }
  }
}

register('fnv1a', () => new Fnv1aAlgorithm())
