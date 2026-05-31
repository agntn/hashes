import { blake2s } from '@noble/hashes/blake2.js'
import { registerNobleAlgorithm } from './noble-algo'

registerNobleAlgorithm({
  name: 'blake2s',
  label: 'BLAKE2s',
  description: 'BLAKE2s 256-bit hash — optimized for 32-bit platforms, smaller state than BLAKE2b',
  family: 'cryptographic',
  hashFn: blake2s,
  digestLength: 32,
  securityNote: 'Up to 256-bit security level',
})
