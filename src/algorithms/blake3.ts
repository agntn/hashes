import { blake3 } from '@noble/hashes/blake3.js'
import { registerNobleAlgorithm } from './noble-algo'

registerNobleAlgorithm({
  name: 'blake3',
  label: 'BLAKE3',
  description: 'BLAKE3 — extremely fast cryptographic hash, parallelizable, 256-bit output',
  family: 'cryptographic',
  hashFn: blake3,
  digestLength: 32,
  hmac: false,
  securityNote: '256-bit security level, Merkle tree structure for parallelism',
})
