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
  meta: { name: 'hash', description: 'Hash input with an algorithm' },
  args: {
    algorithm: { type: 'positional', description: 'Algorithm name (sha256, blake3, md5, ...)', required: true },
    input: { type: 'positional', description: 'Text to hash (or - for stdin)', required: true },
    encoding: { type: 'string', description: 'Output encoding: hex, base64, base64url, binary', alias: 'e', default: 'hex' },
  },
  async run({ args }) {
    const algo = resolveAlgorithm(args.algorithm)
    const opts: HashOptions = { encoding: parseEncoding(args.encoding) }
    const result = algo.hash(args.input, opts)
    if (result.encoding === 'binary') {
      process.stdout.write(result.digest as Uint8Array)
    } else {
      consola.log(result.digest)
    }
  },
})
