import { md5 } from '@noble/hashes/legacy.js'
import { registerNobleAlgorithm } from './noble-algo'

registerNobleAlgorithm({
  name: 'md5',
  label: 'MD5',
  description: 'MD5 128-bit hash — BROKEN for security, still used for checksums and fingerprinting',
  family: 'legacy',
  hashFn: md5,
  digestLength: 16,
  securityNote: 'BROKEN — collision attacks known since 2004. Use only for non-security checksums.',
})
