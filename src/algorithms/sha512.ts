import { sha512 } from '@noble/hashes/sha2.js'
import { registerNobleAlgorithm } from './noble-algo'

registerNobleAlgorithm({
  name: 'sha512',
  label: 'SHA-512',
  description: 'SHA-2 family 512-bit hash — strongest SHA-2 variant, used for high-security applications',
  family: 'cryptographic',
  hashFn: sha512,
  digestLength: 64,
  securityNote: '512-bit security level',
})
