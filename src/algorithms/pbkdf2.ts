import { pbkdf2 as noblePbkdf2 } from '@noble/hashes/pbkdf2.js'
import { sha256, sha384, sha512 } from '@noble/hashes/sha2.js'
import { sha3_256, sha3_512 } from '@noble/hashes/sha3.js'
import { randomBytes } from '@noble/hashes/utils.js'
import type { CHash } from '@noble/hashes/utils.js'
import type { HashAlgorithm, AlgorithmInfo, HashOptions, HashResult, OutputEncoding } from '../core/types'
import { InvalidOptionError, normalizeError } from '../core/errors'
import { toBytes, encodeDigest } from './noble-helper'
import { register } from '../core/registry'

const DIGEST_MAP: Record<string, CHash> = {
  sha256,
  sha384,
  sha512,
  'sha3-256': sha3_256,
  'sha3-512': sha3_512,
}

interface Pbkdf2Options extends HashOptions {
  salt?: string | Uint8Array
  saltEncoding?: 'hex' | 'base64' | 'utf8'
  iterations?: number
  digest?: string
  keyLength?: number
}

class Pbkdf2Algorithm implements HashAlgorithm {
  name(): string { return 'pbkdf2' }

  info(): AlgorithmInfo {
    return {
      name: 'pbkdf2',
      label: 'PBKDF2',
      description: 'PBKDF2 password-based KDF — NIST standard, configurable iterations',
      family: 'password',
      hmac: false,
      options: [
        { name: 'encoding', type: 'string', required: false, default: 'hex', description: 'Output encoding' },
        { name: 'salt', type: 'string', required: false, description: 'Salt (hex string, or auto-generated)' },
        { name: 'iterations', type: 'number', required: false, default: 600000, description: 'Iteration count (OWASP: ≥600000 for SHA-512)' },
        { name: 'digest', type: 'string', required: false, default: 'sha512', description: 'Underlying hash: sha256, sha384, sha512, sha3-256, sha3-512' },
        { name: 'keyLength', type: 'number', required: false, default: 64, description: 'Output key length in bytes' },
      ],
      securityNote: 'OWASP 2023: ≥600000 iterations for SHA-512, ≥210000 for SHA-256.',
    }
  }

  hash(input: string, options?: Pbkdf2Options): HashResult {
    try {
      const encoding: OutputEncoding = options?.encoding ?? 'hex'
      const iterations = options?.iterations ?? 600000
      const digestName = options?.digest ?? 'sha512'
      const keyLength = options?.keyLength ?? 64

      if (iterations < 1) {
        throw new InvalidOptionError('iterations', iterations, 'must be >= 1')
      }

      const hashCtor = DIGEST_MAP[digestName]
      if (!hashCtor) {
        throw new InvalidOptionError('digest', digestName, `unknown digest; use: ${Object.keys(DIGEST_MAP).join(', ')}`)
      }

      let salt: Uint8Array
      if (options?.salt) {
        salt = typeof options.salt === 'string'
          ? Buffer.from(options.salt, options.saltEncoding ?? 'hex')
          : options.salt
      } else {
        salt = randomBytes(32)
      }

      const raw = noblePbkdf2(hashCtor, toBytes(input), salt, { c: iterations, dkLen: keyLength })
      return encodeDigest(raw, 'pbkdf2', 'hash', encoding, { iterations, digest: digestName, keyLength, salt: Buffer.from(salt).toString('hex') })
    } catch (e) {
      throw normalizeError(e, 'pbkdf2')
    }
  }
}

register('pbkdf2', () => new Pbkdf2Algorithm())
