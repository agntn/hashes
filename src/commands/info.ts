import { defineCommand } from 'citty'
import consola from 'consola'
import { resolveAlgorithm } from '../core/resolve'

export default defineCommand({
  meta: { name: 'info', description: 'Show algorithm details' },
  args: {
    algorithm: { type: 'positional', description: 'Algorithm name', required: true },
  },
  run({ args }) {
    const algo = resolveAlgorithm(args.algorithm)
    const info = algo.info()

    consola.log(`\n  ${info.label} (${info.name})`)
    consola.log(`  ${info.description}\n`)
    consola.log(`  Family:    ${info.family}`)
    if (info.digestLength) consola.log(`  Digest:    ${info.digestLength * 8}-bit (${info.digestLength} bytes)`)
    consola.log(`  HMAC:      ${info.hmac ? 'supported' : 'not supported'}`)
    if (info.dependency) consola.log(`  Requires:  ${info.dependency}`)
    if (info.securityNote) consola.log(`  Security:  ${info.securityNote}`)

    if (info.options.length > 0) {
      consola.log('\n  Options:')
      for (const opt of info.options) {
        const def = opt.default !== undefined ? ` (default: ${opt.default})` : ''
        const req = opt.required ? ' [required]' : ''
        consola.log(`    --${opt.name}${req}${def}: ${opt.description}`)
      }
    }
    consola.log('')
  },
})
