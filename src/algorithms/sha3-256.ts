import { sha3_256 } from '@noble/hashes/sha3.js'
import { registerNobleAlgorithm } from './noble-algo'

registerNobleAlgorithm({
  name: 'sha3-256',
  label: 'SHA3-256',
  description: 'SHA-3 (Keccak) 256-bit hash — NIST standard, different internal structure from SHA-2',
  family: 'cryptographic',
  hashFn: sha3_256,
  digestLength: 32,
  securityNote: '256-bit security level, sponge construction',
})
