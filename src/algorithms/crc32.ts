import type { BinaryLike } from 'node:crypto'
import type { HashAlgorithm, AlgorithmInfo, HashOptions, HashResult, OutputEncoding } from '../core/types'
import { normalizeError } from '../core/errors'
import { register } from '../core/registry'

/** CRC32 lookup table (polynomial 0xEDB88320). */
const TABLE = new Uint32Array(256)
for (let i = 0; i < 256; i++) {
  let c = i
  for (let j = 0; j < 8; j++) {
    c = (c & 1) ? (0xEDB88320 ^ (c >>> 1)) : (c >>> 1)
  }
  TABLE[i] = c
}

function crc32Compute(data: Uint8Array): number {
  let crc = 0xFFFFFFFF
  for (let i = 0; i < data.length; i++) {
    crc = TABLE[(crc ^ data[i]!) & 0xFF]! ^ (crc >>> 8)
  }
  return (crc ^ 0xFFFFFFFF) >>> 0
}

function toBytes(input: string | Uint8Array): Uint8Array {
  return typeof input === 'string' ? new TextEncoder().encode(input) : input
}

class Crc32Algorithm implements HashAlgorithm {
  name(): string { return 'crc32' }

  info(): AlgorithmInfo {
    return {
      name: 'crc32',
      label: 'CRC-32',
      description: 'CRC-32 — cyclic redundancy check used in ZIP, PNG, gzip, network protocols',
      family: 'non-cryptographic',
      digestLength: 4,
      hmac: false,
      options: [
        { name: 'encoding', type: 'string', required: false, default: 'hex', description: 'Output encoding: hex, base64, base64url, binary' },
      ],
      securityNote: 'NOT for security — error-detection checksum only',
    }
  }

  hash(input: BinaryLike | string, options?: HashOptions): HashResult {
    try {
      const encoding: OutputEncoding = options?.encoding ?? 'hex'
      const bytes = toBytes(input as string | Uint8Array)
      const crc = crc32Compute(bytes)
      const raw = Buffer.alloc(4)
      raw.writeUInt32BE(crc)

      if (encoding === 'binary') {
        return {
          digest: new Uint8Array(raw),
          algorithm: 'crc32',
          operation: 'hash',
          encoding,
          digestLength: 4,
          options: { encoding },
        }
      }

      const outEncoding = encoding === 'base64url' ? 'base64url' : encoding
      return {
        digest: raw.toString(outEncoding as 'hex' | 'base64' | 'base64url'),
        algorithm: 'crc32',
        operation: 'hash',
        encoding,
        digestLength: 4,
        options: { encoding },
      }
    } catch (e) {
      throw normalizeError(e, 'crc32')
    }
  }
}

register('crc32', () => new Crc32Algorithm())
