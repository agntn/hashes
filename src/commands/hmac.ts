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
  meta: { name: 'hmac', description: 'Compute HMAC with an algorithm' },
  args: {
    algorithm: { type: 'positional', description: 'Algorithm name (sha256, sha512, blake2b, ...)', required: true },
    input: { type: 'positional', description: 'Text to HMAC', required: true },
    key: { type: 'positional', description: 'HMAC key', required: true },
    encoding: { type: 'string', description: 'Output encoding: hex, base64, base64url, binary', alias: 'e', default: 'hex' },
  },
  async run({ args }) {
    const algo = resolveAlgorithm(args.algorithm)
    const info = algo.info()
    if (!info.hmac) {
      consola.error(`Algorithm "${args.algorithm}" does not support HMAC mode`)
      process.exit(1)
    }
    const opts: HashOptions = { encoding: parseEncoding(args.encoding), key: args.key }
    const result = algo.hash(args.input, opts)
    if (result.encoding === 'binary') {
      process.stdout.write(result.digest as Uint8Array)
    } else {
      consola.log(result.digest)
    }
  },
})
