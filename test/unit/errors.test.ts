import { describe, it, expect } from "vitest"
import {
  HashError,
  UnknownAlgorithmError,
  InvalidOptionError,
  MissingOptionError,
  DependencyError,
  normalizeError,
} from "../../src/core/errors"

describe("error hierarchy", () => {
  it("HashError is base Error with name=HashError", () => {
    const e = new HashError("test")
    expect(e).toBeInstanceOf(Error)
    expect(e).toBeInstanceOf(HashError)
    expect(e.name).toBe("HashError")
    expect(e.message).toBe("test")
  })

  it("UnknownAlgorithmError includes algorithm name", () => {
    const e = new UnknownAlgorithmError("fnv99")
    expect(e).toBeInstanceOf(HashError)
    expect(e.algorithm).toBe("fnv99")
    expect(e.message).toContain("fnv99")
    expect(e.name).toBe("UnknownAlgorithmError")
  })

  it("InvalidOptionError includes option/value/reason", () => {
    const e = new InvalidOptionError("encoding", "junk", "unknown format")
    expect(e.option).toBe("encoding")
    expect(e.value).toBe("junk")
    expect(e.reason).toBe("unknown format")
    expect(e.message).toContain("encoding=junk")
  })

  it("MissingOptionError includes option name", () => {
    const e = new MissingOptionError("key")
    expect(e.option).toBe("key")
    expect(e.message).toContain("key")
  })

  it("DependencyError includes algorithm and dependency", () => {
    const e = new DependencyError("blake3", "@noble/hashes")
    expect(e.algorithm).toBe("blake3")
    expect(e.dependency).toBe("@noble/hashes")
    expect(e.message).toContain("blake3")
    expect(e.message).toContain("@noble/hashes")
  })
})

describe("normalizeError", () => {
  it("passes through HashError as-is", () => {
    const e = new UnknownAlgorithmError("foo")
    expect(normalizeError(e)).toBe(e)
  })

  it("wraps Error into HashError with message", () => {
    const e = new Error("disk full")
    const out = normalizeError(e)
    expect(out).toBeInstanceOf(HashError)
    expect(out.message).toBe("disk full")
  })

  it("wraps non-Error into HashError with String coercion", () => {
    const out = normalizeError("oops" as unknown)
    expect(out).toBeInstanceOf(HashError)
    expect(out.message).toBe("oops")
  })

  it("prefixes algorithm when provided", () => {
    const out = normalizeError(new Error("bad input"), "fnv1a")
    expect(out.message).toBe("[fnv1a] bad input")
  })
})
