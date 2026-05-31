import { scrypt as nobleScrypt } from '@noble/hashes/scrypt.js'
import { randomBytes } from '@noble/hashes/utils.js'
import type { HashAlgorithm, AlgorithmInfo, HashOptions, HashResult, OutputEncoding } from '../core/types'
import { InvalidOptionError, normalizeError } from '../core/errors'
import { toBytes, encodeDigest } from './noble-helper'
import { register } from '../core/registry'

interface ScryptOptions extends HashOptions {
  salt?: string | Uint8Array
  saltEncoding?: 'hex' | 'base64' | 'utf8'
  N?: number
  r?: number
  p?: number
  keyLength?: number
}

class ScryptAlgorithm implements HashAlgorithm {
  name(): string { return 'scrypt' }

  info(): AlgorithmInfo {
    return {
      name: 'scrypt',
      label: 'scrypt',
      description: 'scrypt password-based KDF — memory-hard, resistant to hardware attacks',
      family: 'password',
      hmac: false,
      options: [
        { name: 'encoding', type: 'string', required: false, default: 'hex', description: 'Output encoding' },
        { name: 'salt', type: 'string', required: false, description: 'Salt (hex string, or auto-generated)' },
        { name: 'N', type: 'number', required: false, default: 16384, description: 'CPU/memory cost (power of 2)' },
        { name: 'r', type: 'number', required: false, default: 8, description: 'Block size' },
        { name: 'p', type: 'number', required: false, default: 1, description: 'Parallelization' },
        { name: 'keyLength', type: 'number', required: false, default: 64, description: 'Output key length in bytes' },
      ],
      securityNote: 'Memory-hard KDF — resistant to ASIC/GPU attacks. Recommended N≥16384 for passwords.',
    }
  }

  hash(input: string, options?: ScryptOptions): HashResult {
    try {
      const encoding: OutputEncoding = options?.encoding ?? 'hex'
      const N = options?.N ?? 16384
      const r = options?.r ?? 8
      const p = options?.p ?? 1
      const keyLength = options?.keyLength ?? 64

      if (N < 2 || (N & (N - 1)) !== 0) {
        throw new InvalidOptionError('N', N, 'must be a power of 2 and >= 2')
      }

      let salt: Uint8Array
      if (options?.salt) {
        salt = typeof options.salt === 'string'
          ? Buffer.from(options.salt, options.saltEncoding ?? 'hex')
          : options.salt
      } else {
        salt = randomBytes(32)
      }

      const raw = nobleScrypt(toBytes(input), salt, { N, r, p, dkLen: keyLength })
      return encodeDigest(raw, 'scrypt', 'hash', encoding, { N, r, p, keyLength, salt: Buffer.from(salt).toString('hex') })
    } catch (e) {
      throw normalizeError(e, 'scrypt')
    }
  }
}

register('scrypt', () => new ScryptAlgorithm())
