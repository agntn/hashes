import { sha384 } from '@noble/hashes/sha2.js'
import { registerNobleAlgorithm } from './noble-algo'

registerNobleAlgorithm({
  name: 'sha384',
  label: 'SHA-384',
  description: 'SHA-2 family 384-bit hash — truncated SHA-512, used in TLS and government applications',
  family: 'cryptographic',
  hashFn: sha384,
  digestLength: 48,
  securityNote: '384-bit security level',
})
