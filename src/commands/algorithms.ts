import { defineCommand } from 'citty'
import consola from 'consola'
import { algorithms as listAlgorithms, create } from '../core/registry'

export default defineCommand({
  meta: { name: 'algorithms', description: 'List all registered algorithms' },
  args: {
    family: { type: 'string', description: 'Filter by family: cryptographic, legacy, non-cryptographic, password', alias: 'f' },
  },
  run({ args }) {
    const names = listAlgorithms()
    const rows: Array<{ name: string; family: string; digest: string; hmac: string; label: string }> = []

    for (const name of names) {
      const algo = create(name)
      const info = algo.info()
      if (args.family && info.family !== args.family) continue
      rows.push({
        name: info.name,
        family: info.family,
        digest: info.digestLength ? `${info.digestLength * 8}-bit` : 'variable',
        hmac: info.hmac ? '✓' : '✗',
        label: info.label,
      })
    }

    if (rows.length === 0) {
      consola.log(args.family ? `No algorithms in family "${args.family}"` : 'No algorithms registered')
      return
    }

    // Table output
    const w = { name: 12, family: 18, digest: 10, hmac: 4, label: 0 }
    for (const r of rows) {
      w.name = Math.max(w.name, r.name.length)
      w.family = Math.max(w.family, r.family.length)
      w.label = Math.max(w.label, r.label.length)
    }

    const header = `${'Name'.padEnd(w.name)}  ${'Family'.padEnd(w.family)}  ${'Digest'.padEnd(w.digest)}  ${'HMAC'.padStart(w.hmac)}  Label`
    consola.log(header)
    consola.log('─'.repeat(header.length))
    for (const r of rows) {
      consola.log(`${r.name.padEnd(w.name)}  ${r.family.padEnd(w.family)}  ${r.digest.padEnd(w.digest)}  ${r.hmac.padStart(w.hmac)}  ${r.label}`)
    }
  },
})
