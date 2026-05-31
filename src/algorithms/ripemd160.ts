import { ripemd160 } from '@noble/hashes/legacy.js'
import { registerNobleAlgorithm } from './noble-algo'

registerNobleAlgorithm({
  name: 'ripemd160',
  label: 'RIPEMD-160',
  description: 'RIPEMD-160 160-bit hash — used in Bitcoin address derivation (Hash160 = RIPEMD160(SHA256(x)))',
  family: 'cryptographic',
  hashFn: ripemd160,
  digestLength: 20,
  securityNote: '160-bit security level, used in Bitcoin',
})
