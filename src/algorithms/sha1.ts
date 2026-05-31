import { sha1 } from '@noble/hashes/legacy.js'
import { registerNobleAlgorithm } from './noble-algo'

registerNobleAlgorithm({
  name: 'sha1',
  label: 'SHA-1',
  description: 'SHA-1 160-bit hash — BROKEN for security (SHAttered 2017), still used in Git and legacy systems',
  family: 'legacy',
  hashFn: sha1,
  digestLength: 20,
  securityNote: 'BROKEN — practical collision attack (SHAttered). Use only for legacy compatibility.',
})
