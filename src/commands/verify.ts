import { defineCommand } from 'citty'
import consola from 'consola'
import { resolveAlgorithm } from '../core/resolve'
import type { HashOptions, OutputEncoding } from '../core/types'

function parseEncoding(value: string | undefined): OutputEncoding {
  const enc = (value ?? 'hex') as OutputEncoding
  if (!['hex', 'base64', 'base64url', 'binary'].includes(enc)) {
    consola.error(`Invalid encoding: "${value}". Use: hex, base64, base64url, binary`)
    process.exit(1)
  }
  return enc
}

export default defineCommand({
  meta: { name: 'verify', description: 'Verify input against an expected hash' },
  args: {
    algorithm: { type: 'positional', description: 'Algorithm name', required: true },
    input: { type: 'positional', description: 'Text to hash', required: true },
    expected: { type: 'positional', description: 'Expected hash digest', required: true },
    encoding: { type: 'string', description: 'Encoding of expected hash', alias: 'e', default: 'hex' },
  },
  run({ args }) {
    const algo = resolveAlgorithm(args.algorithm)
    const opts: HashOptions = { encoding: parseEncoding(args.encoding) }
    const result = algo.hash(args.input, opts)
    const actual = typeof result.digest === 'string' ? result.digest.toLowerCase() : ''
    const expected = args.expected.toLowerCase()

    if (actual === expected) {
      consola.success(`✓ MATCH — ${algo.name()}(${args.input}) = ${actual}`)
    } else {
      consola.error(`✗ MISMATCH`)
      consola.log(`  Expected: ${expected}`)
      consola.log(`  Actual:   ${actual}`)
      process.exit(1)
    }
  },
})
