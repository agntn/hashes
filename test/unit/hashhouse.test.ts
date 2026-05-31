import { describe, it, expect } from 'vitest'
// Import registers all algorithms
import { create, algorithms, has, resolveAlgorithm } from '../../src/index'

describe('hashhouse registry', () => {
  it('registers all built-in algorithms', () => {
    const names = algorithms()
    expect(names.length).toBeGreaterThanOrEqual(16)
    expect(names).toContain('sha256')
    expect(names).toContain('blake2b')
    expect(names).toContain('md5')
    expect(names).toContain('crc32')
    expect(names).toContain('fnv1a')
    expect(names).toContain('scrypt')
    expect(names).toContain('pbkdf2')
  })

  it('has() returns true for registered algorithms', () => {
    expect(has('sha256')).toBe(true)
    expect(has('nonexistent')).toBe(false)
  })

  it('resolveAlgorithm normalizes names', () => {
    const algo = resolveAlgorithm('SHA256')
    expect(algo.name()).toBe('sha256')
  })

  it('resolveAlgorithm throws for unknown', () => {
    expect(() => resolveAlgorithm('nonexistent')).toThrow('Unknown algorithm')
  })
})

describe('SHA-256', () => {
  it('hashes known test vectors', () => {
    const sha256 = create('sha256')
    // SHA-256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
    const empty = sha256.hash('')
    expect(empty.digest).toBe('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855')
    expect(empty.algorithm).toBe('sha256')
    expect(empty.operation).toBe('hash')
    expect(empty.digestLength).toBe(32)

    // SHA-256("abc") = ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
    const abc = sha256.hash('abc')
    expect(abc.digest).toBe('ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad')
  })

  it('supports HMAC-SHA256', () => {
    const sha256 = create('sha256')
    const hmac = sha256.hash('hello', { key: 'secret' })
    expect(hmac.operation).toBe('hmac')
    expect(hmac.digest).toMatch(/^[a-f0-9]{64}$/)
  })

  it('supports base64 encoding', () => {
    const sha256 = create('sha256')
    const result = sha256.hash('test', { encoding: 'base64' })
    expect(result.encoding).toBe('base64')
    // Should be valid base64
    expect(() => Buffer.from(result.digest as string, 'base64')).not.toThrow()
  })
})

describe('MD5 (legacy)', () => {
  it('hashes known test vectors', () => {
    const md5 = create('md5')
    // MD5("") = d41d8cd98f00b204e9800998ecf8427e
    const empty = md5.hash('')
    expect(empty.digest).toBe('d41d8cd98f00b204e9800998ecf8427e')
    expect(empty.algorithm).toBe('md5')

    // MD5("hello") = 5d41402abc4b2a76b9719d911017c592
    const hello = md5.hash('hello')
    expect(hello.digest).toBe('5d41402abc4b2a76b9719d911017c592')
  })
})

describe('SHA-1 (legacy)', () => {
  it('hashes known test vectors', () => {
    const sha1 = create('sha1')
    // SHA1("abc") = a9993e364706816aba3e25717850c26c9cd0d89d
    const abc = sha1.hash('abc')
    expect(abc.digest).toBe('a9993e364706816aba3e25717850c26c9cd0d89d')
  })
})

describe('CRC-32', () => {
  it('computes known CRC-32 values', () => {
    const crc32 = create('crc32')
    // CRC-32("hello") = 3610a686
    const hello = crc32.hash('hello')
    expect(hello.digest).toBe('3610a686')
    expect(hello.digestLength).toBe(4)
    expect(create('crc32').info().family).toBe('non-cryptographic')
  })
})

describe('FNV-1a', () => {
  it('computes FNV-1a 64-bit', () => {
    const fnv = create('fnv1a')
    const result = fnv.hash('hello')
    expect(result.digest).toMatch(/^[a-f0-9]{16}$/)  // 64-bit = 16 hex chars
    expect(result.digestLength).toBe(8)
  })
})

describe('scrypt', () => {
  it('hashes with auto-generated salt', () => {
    const scrypt = create('scrypt')
    const result = scrypt.hash('password123')
    expect(result.digest).toMatch(/^[a-f0-9]{128}$/)  // 64 bytes = 128 hex chars
    expect(result.operation).toBe('hash')
    expect(result.options).toHaveProperty('salt')
    expect(result.options).toHaveProperty('N', 16384)
  })

  it('produces same output with same salt', () => {
    const scrypt = create('scrypt')
    const salt = 'deadbeef00000000deadbeef00000000deadbeef00000000deadbeef00000000'
    const r1 = scrypt.hash('test', { salt })
    const r2 = scrypt.hash('test', { salt })
    expect(r1.digest).toBe(r2.digest)
  })
})

describe('pbkdf2', () => {
  it('hashes with auto-generated salt', () => {
    const pbkdf2 = create('pbkdf2')
    const result = pbkdf2.hash('password123')
    expect(result.digest).toMatch(/^[a-f0-9]{128}$/)  // 64 bytes = 128 hex chars
    expect(result.options).toHaveProperty('iterations', 600000)
    expect(result.options).toHaveProperty('digest', 'sha512')
  })

  it('produces same output with same salt and iterations', () => {
    const pbkdf2 = create('pbkdf2')
    const salt = 'deadbeef00000000deadbeef00000000deadbeef00000000deadbeef00000000'
    const r1 = pbkdf2.hash('test', { salt, iterations: 100000 })
    const r2 = pbkdf2.hash('test', { salt, iterations: 100000 })
    expect(r1.digest).toBe(r2.digest)
  })
})

describe('algorithm info', () => {
  it('every algorithm reports correct info', () => {
    for (const name of algorithms()) {
      const algo = create(name)
      const info = algo.info()
      expect(info.name).toBe(name)
      expect(info.label).toBeTruthy()
      expect(info.description).toBeTruthy()
      expect(info.family).toBeTruthy()
      expect(typeof info.hmac).toBe('boolean')
    }
  })

  it('families are correct', () => {
    expect(create('sha256').info().family).toBe('cryptographic')
    expect(create('md5').info().family).toBe('legacy')
    expect(create('crc32').info().family).toBe('non-cryptographic')
    expect(create('scrypt').info().family).toBe('password')
  })
})
