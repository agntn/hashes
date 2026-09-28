/**
 * Shared helper wrapping @noble/hashes API into the HashResult shape.
 * Every noble-backed algorithm delegates here.
 */
import type { HashResult, HashOptions, OutputEncoding } from '../core/types'
import { normalizeError } from '../core/errors'

/** Convert string → Uint8Array (UTF-8). */
export function toBytes(input: string | Uint8Array): Uint8Array {
  if (typeof input === 'string') return new TextEncoder().encode(input)
  return input
}

/** Encode raw bytes to the requested output format. */
export function encodeDigest(
  raw: Uint8Array,
  algorithm: string,
  operation: 'hash' | 'hmac',
  encoding: OutputEncoding,
  extraOptions?: Record<string, unknown>,
): HashResult {
  let digest: string | Uint8Array
  if (encoding === 'binary') {
    digest = raw
  } else if (encoding === 'base64url') {
    // base64url without padding
    const b64 = Buffer.from(raw).toString('base64')
    digest = b64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
  } else {
    digest = Buffer.from(raw).toString(encoding as 'hex' | 'base64')
  }

  return {
    digest,
    algorithm,
    operation,
    encoding,
    digestLength: raw.length,
    options: { encoding, ...extraOptions },
  }
}

/** Wrap a noble hash call into HashResult. */
export function nobleHash(
  algorithm: string,
  hashFn: () => Uint8Array,
  options?: HashOptions,
): HashResult {
  try {
    const encoding: OutputEncoding = options?.encoding ?? 'hex'
    const raw = hashFn()
    return encodeDigest(raw, algorithm, 'hash', encoding)
  } catch (e) {
    throw normalizeError(e, algorithm)
  }
}

/** Wrap a noble HMAC call into HashResult. */
export function nobleHmac(
  algorithm: string,
  hmacFn: () => Uint8Array,
  options?: HashOptions,
): HashResult {
  try {
    const encoding: OutputEncoding = options?.encoding ?? 'hex'
    const raw = hmacFn()
    return encodeDigest(raw, algorithm, 'hmac', encoding, { hmac: true })
  } catch (e) {
    throw normalizeError(e, algorithm)
  }
}
