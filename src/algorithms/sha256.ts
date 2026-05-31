import { sha256 } from '@noble/hashes/sha2.js'
import { registerNobleAlgorithm } from './noble-algo'

registerNobleAlgorithm({
  name: 'sha256',
  label: 'SHA-256',
  description: 'SHA-2 family 256-bit hash — widely used for digital signatures, certificates, and integrity checks',
  family: 'cryptographic',
  hashFn: sha256,
  digestLength: 32,
  securityNote: '256-bit security level',
})
