import { blake2b } from '@noble/hashes/blake2.js'
import { registerNobleAlgorithm } from './noble-algo'

registerNobleAlgorithm({
  name: 'blake2b',
  label: 'BLAKE2b',
  description: 'BLAKE2b 512-bit hash — fast, secure, used by many modern protocols (Argon2, WireGuard)',
  family: 'cryptographic',
  hashFn: blake2b,
  digestLength: 64,
  securityNote: 'Up to 512-bit security level',
})
