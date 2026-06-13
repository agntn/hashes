/**
 * hashhouse FNV-1a + registry tests.
 */
import { describe, it, expect, beforeAll } from 'vitest'
import { algorithms, create, has, builtinAlgorithms } from '../../src/core/index'
import '../../src/algorithms/index'  // register all

beforeAll(() => {
  // Algorithms are auto-registered on import of algorithms/index
})

describe('FNV-1a (fnv1a)', () => {
  it('is registered', () => {
    expect(has('fnv1a')).toBe(true)
  })

  it('produces 8-byte digest with binary encoding', () => {
    const r = create('fnv1a').hash('hello', { encoding: 'binary' })
    expect(r.algorithm).toBe('fnv1a')
    expect(r.digestLength).toBe(8)
    expect(r.encoding).toBe('binary')
    if (r.digest instanceof Uint8Array) {
      expect(r.digest.length).toBe(8)
    }
  })

  it('produces hex string by default', () => {
    const r = create('fnv1a').hash('hello')
    expect(typeof r.digest).toBe('string')
    expect(r.encoding).toBe('hex')
    expect((r.digest as string).length).toBe(16)  // 8 bytes = 16 hex chars
  })

  it('produces consistent hashes for same input', () => {
    const a = create('fnv1a').hash('test')
    const b = create('fnv1a').hash('test')
    expect(a.digest).toBe(b.digest)
  })

  it('produces different hashes for different inputs', () => {
    const a = create('fnv1a').hash('test1')
    const b = create('fnv1a').hash('test2')
    expect(a.digest).not.toBe(b.digest)
  })

  it('handles empty string', () => {
    const r = create('fnv1a').hash('')
    expect(r.algorithm).toBe('fnv1a')
  })

  it('handles UTF-8 strings', () => {
    const r = create('fnv1a').hash('héllo wörld')
    expect(r.digest).toBeDefined()
  })
})

describe('hashhouse registry', () => {
  it('builtinAlgorithms lists all built-in algorithms', () => {
    expect(builtinAlgorithms.length).toBeGreaterThan(0)
    expect(builtinAlgorithms).toContain('fnv1a')
  })

  it('algorithms() returns array of registered algorithm names', () => {
    const all = algorithms()
    expect(all.length).toBeGreaterThan(0)
    for (const name of all) {
      expect(typeof name).toBe('string')
      expect(name.length).toBeGreaterThan(0)
    }
    expect(all).toContain('fnv1a')
  })

  it('has() returns true for registered, false for unknown', () => {
    expect(has('fnv1a')).toBe(true)
    expect(has('nonexistent-algo-xyz')).toBe(false)
  })
})
