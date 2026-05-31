/**
 * XXH64 — pure JS implementation (no external dependency).
 * Based on the xxHash specification by Yann Collet.
 */
import type { BinaryLike } from 'node:crypto'
import type { HashAlgorithm, AlgorithmInfo, HashOptions, HashResult, OutputEncoding } from '../core/types'
import { normalizeError } from '../core/errors'
import { register } from '../core/registry'

const PRIME64_1 = 0x9E3779B185EBCA87n
const PRIME64_2 = 0x14DEF9DEA2F79CD6n
const PRIME64_3 = 0x165667B19E3779F9n
const PRIME64_4 = 0x85EBCA77C2B2AE63n
const PRIME64_5 = 0x27D4EB2F165667C5n
const MASK64 = 0xFFFFFFFFFFFFFFFFn

function rotl64(x: bigint, r: number): bigint {
  return ((x << BigInt(r)) | (x >> BigInt(64 - r))) & MASK64
}

function readU64LE(buf: Uint8Array, off: number): bigint {
  return (
    BigInt(buf[off]!) |
    (BigInt(buf[off + 1]!) << 8n) |
    (BigInt(buf[off + 2]!) << 16n) |
    (BigInt(buf[off + 3]!) << 24n) |
    (BigInt(buf[off + 4]!) << 32n) |
    (BigInt(buf[off + 5]!) << 40n) |
    (BigInt(buf[off + 6]!) << 48n) |
    (BigInt(buf[off + 7]!) << 56n)
  ) & MASK64
}

function readU32LE(buf: Uint8Array, off: number): number {
  return (buf[off]! | (buf[off + 1]! << 8) | (buf[off + 2]! << 16) | (buf[off + 3]! << 24)) >>> 0
}

function xxh64(data: Uint8Array, seed: bigint = 0n): bigint {
  const len = data.length
  let h: bigint
  let off = 0

  if (len >= 32) {
    let acc1 = (seed + PRIME64_1 + PRIME64_2) & MASK64
    let acc2 = (seed + PRIME64_2) & MASK64
    let acc3 = (seed + 0n) & MASK64
    let acc4 = (seed - PRIME64_1 + MASK64 + 1n) & MASK64

    const limit = len - 32
    while (off <= limit) {
      acc1 = (rotl64((acc1 + readU64LE(data, off) * PRIME64_2) & MASK64, 31) * PRIME64_1) & MASK64
      off += 8
      acc2 = (rotl64((acc2 + readU64LE(data, off) * PRIME64_2) & MASK64, 31) * PRIME64_1) & MASK64
      off += 8
      acc3 = (rotl64((acc3 + readU64LE(data, off) * PRIME64_2) & MASK64, 31) * PRIME64_1) & MASK64
      off += 8
      acc4 = (rotl64((acc4 + readU64LE(data, off) * PRIME64_2) & MASK64, 31) * PRIME64_1) & MASK64
      off += 8
    }

    h = (rotl64(acc1, 1) + rotl64(acc2, 7) + rotl64(acc3, 12) + rotl64(acc4, 18)) & MASK64
    h = (((h ^ ((acc1 * PRIME64_2) & MASK64)) * PRIME64_1 + PRIME64_4) & MASK64)
    h = (((h ^ ((acc2 * PRIME64_2) & MASK64)) * PRIME64_1 + PRIME64_4) & MASK64)
    h = (((h ^ ((acc3 * PRIME64_2) & MASK64)) * PRIME64_1 + PRIME64_4) & MASK64)
    h = (((h ^ ((acc4 * PRIME64_2) & MASK64)) * PRIME64_1 + PRIME64_4) & MASK64)
  } else {
    h = (seed + PRIME64_5) & MASK64
  }

  h = (h + BigInt(len)) & MASK64

  while (off + 8 <= len) {
    h = (rotl64((h ^ readU64LE(data, off) * PRIME64_2) & MASK64, 27) * PRIME64_1 + PRIME64_4) & MASK64
    off += 8
  }

  if (off + 4 <= len) {
    h = (rotl64((h ^ BigInt(readU32LE(data, off)) * PRIME64_1) & MASK64, 23) * PRIME64_2 + PRIME64_3) & MASK64
    off += 4
  }

  while (off < len) {
    h = (rotl64((h ^ BigInt(data[off]!) * PRIME64_5) & MASK64, 11) * PRIME64_1) & MASK64
    off++
  }

  h = ((h ^ (h >> 33n)) * PRIME64_2) & MASK64
  h = ((h ^ (h >> 29n)) * PRIME64_3) & MASK64
  h = h ^ (h >> 32n)

  return h & MASK64
}

class XxhashAlgorithm implements HashAlgorithm {
  name(): string { return 'xxhash' }

  info(): AlgorithmInfo {
    return {
      name: 'xxhash',
      label: 'xxHash (XXH64)',
      description: 'xxHash 64-bit — extremely fast non-cryptographic hash, used in databases and compression',
      family: 'non-cryptographic',
      digestLength: 8,
      hmac: false,
      options: [
        { name: 'encoding', type: 'string', required: false, default: 'hex', description: 'Output encoding: hex, base64, base64url, binary' },
        { name: 'seed', type: 'number', required: false, default: 0, description: 'Seed value for xxHash' },
      ],
      securityNote: 'NOT for security — fast hash for hash tables, bloom filters, checksums',
    }
  }

  hash(input: BinaryLike | string, options?: HashOptions & { seed?: number }): HashResult {
    try {
      const encoding: OutputEncoding = options?.encoding ?? 'hex'
      const seed = BigInt(options?.seed ?? 0)
      const bytes = typeof input === 'string'
        ? new TextEncoder().encode(input)
        : new Uint8Array(input as Uint8Array)
      const hash = xxh64(bytes, seed)
      const raw = Buffer.alloc(8)
      raw.writeBigUInt64BE(hash)

      if (encoding === 'binary') {
        return {
          digest: new Uint8Array(raw),
          algorithm: 'xxhash',
          operation: 'hash',
          encoding,
          digestLength: 8,
          options: { encoding, seed: options?.seed ?? 0 },
        }
      }

      const outEncoding = encoding === 'base64url' ? 'base64url' : encoding
      return {
        digest: raw.toString(outEncoding as 'hex' | 'base64' | 'base64url'),
        algorithm: 'xxhash',
        operation: 'hash',
        encoding,
        digestLength: 8,
        options: { encoding, seed: options?.seed ?? 0 },
      }
    } catch (e) {
      throw normalizeError(e, 'xxhash')
    }
  }
}

register('xxhash', () => new XxhashAlgorithm())
