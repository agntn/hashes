import { sha3_512 } from '@noble/hashes/sha3.js'
import { registerNobleAlgorithm } from './noble-algo'

registerNobleAlgorithm({
  name: 'sha3-512',
  label: 'SHA3-512',
  description: 'SHA-3 (Keccak) 512-bit hash — NIST standard, strongest SHA-3 variant',
  family: 'cryptographic',
  hashFn: sha3_512,
  digestLength: 64,
  securityNote: '512-bit security level, sponge construction',
})
