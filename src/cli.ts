import { runMain, defineCommand } from 'citty'
import { normalizeMainArgs } from './cli-args'
import { version } from './version'

// Register all algorithms
import './algorithms/index'

const main = defineCommand({
  meta: {
    name: 'hashes',
    version,
    description: 'Unified hashing algorithm CLI',
  },
  subCommands: {
    hash: () => import('./commands/hash').then((m) => m.default),
    hmac: () => import('./commands/hmac').then((m) => m.default),
    algorithms: () => import('./commands/algorithms').then((m) => m.default),
    info: () => import('./commands/info').then((m) => m.default),
    verify: () => import('./commands/verify').then((m) => m.default),
  },
})

await runMain(main, { rawArgs: normalizeMainArgs(process.argv.slice(2)) })
