# @agntn/hashes

Unified hashing algorithm library for agents — CLI + programmatic API + Pi extension.

## Features

- **16 built-in algorithms** across 4 families (cryptographic, legacy, non-cryptographic, password/KDF)
- Self-registering provider pattern — add new algorithms with a single file
- CLI (`hashes`) for quick hashing, HMAC, verification, and algorithm discovery
- Programmatic API with typed results
- Pi agent extension (`hash_compute`, `hash_hmac`, `hash_verify`, `hash_algorithms`)
- Zero config — algorithms register on import

## Algorithms

| Name | Family | Digest | HMAC | Description |
|------|--------|--------|------|-------------|
| `sha256` | cryptographic | 256-bit | ✓ | SHA-2 family, widely used for signatures and integrity |
| `sha384` | cryptographic | 384-bit | ✓ | SHA-2 family, truncated SHA-512 |
| `sha512` | cryptographic | 512-bit | ✓ | SHA-2 family, 512-bit variant |
| `sha3-256` | cryptographic | 256-bit | ✓ | SHA-3 (Keccak), NIST standard |
| `sha3-512` | cryptographic | 512-bit | ✓ | SHA-3 (Keccak), 512-bit variant |
| `blake2b` | cryptographic | 256-bit | ✓ | BLAKE2 — fast, secure, parallelizable |
| `blake2s` | cryptographic | 256-bit | ✓ | BLAKE2 — optimized for 32-bit platforms |
| `blake3` | cryptographic | 256-bit | ✗ | BLAKE3 — extremely fast, Merkle tree parallelism |
| `ripemd160` | cryptographic | 160-bit | ✓ | RIPEMD-160, used in Bitcoin addresses |
| `md5` | legacy | 128-bit | ✓ | MD5 — not collision-resistant, checksums only |
| `sha1` | legacy | 160-bit | ✓ | SHA-1 — deprecated for security, legacy checksums |
| `crc32` | non-cryptographic | 32-bit | ✗ | CRC-32 — fast file/data integrity check |
| `xxhash` | non-cryptographic | 64-bit | ✗ | xxHash — extremely fast non-cryptographic hash |
| `fnv1a` | non-cryptographic | 64-bit | ✗ | FNV-1a — simple, fast hash for hash tables |
| `scrypt` | password | variable | ✗ | scrypt KDF — memory-hard, ASIC-resistant |
| `pbkdf2` | password | variable | ✓ | PBKDF2 — standard password-based KDF |

## Install

```bash
pnpm install
pnpm build
```

Requires Node ≥ 25.

## CLI

The `hashes` binary provides a command-line interface.

```bash
# Hash text (default algorithm: sha256)
hashes sha256 "hello world"
hashes md5 "hello world"
hashes blake3 "hello world"

# HMAC
hashes hmac sha256 "message" "secret-key"

# Verify input against expected hash
hashes verify sha256 "hello" "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"

# List all algorithms
hashes algorithms
hashes algorithms --family cryptographic

# Algorithm details
hashes info sha256
hashes info scrypt

# Output encodings
hashes sha256 "test" --encoding base64
hashes sha256 "test" -e base64url
hashes sha256 "test" -e binary > output.bin
```

Default behavior: `hashes <text>` is shorthand for `hashes hash <text>` (resolves algorithm from name or defaults to sha256).

## Programmatic API

```typescript
import { create, algorithms, has, resolveAlgorithm } from '@agntn/hashes'

// Direct creation
const sha256 = create('sha256')
const result = sha256.hash('hello world')
console.log(result.digest)     // hex string
console.log(result.digestLength) // 32

// HMAC
const hmac = sha256.hash('message', { key: 'secret' })
console.log(hmac.operation)   // 'hmac'

// Encoding options
const b64 = sha256.hash('test', { encoding: 'base64' })
const url = sha256.hash('test', { encoding: 'base64url' })
const bin = sha256.hash('test', { encoding: 'binary' }) // Uint8Array

// Discovery
const names = algorithms()    // ['sha256', 'sha384', ...]
has('blake3')                 // true
const algo = resolveAlgorithm('SHA256') // normalizes name

// Metadata
const info = sha256.info()
console.log(info.family)      // 'cryptographic'
console.log(info.hmac)        // true
console.log(info.digestLength) // 32
```

### Adding a new algorithm

Each algorithm is a self-registering module. Create a file in `src/algorithms/`:

```typescript
import { registerNobleAlgorithm } from './noble-algo'
import { sha256 } from '@noble/hashes/sha2.js'

registerNobleAlgorithm({
  name: 'my-algo',
  label: 'My Algorithm',
  description: 'Description of the algorithm',
  family: 'cryptographic',
  hashFn: sha256, // @noble/hashes CHash
  digestLength: 32,
})
```

Then add `import './my-algo'` to `src/algorithms/index.ts`. The algorithm is available immediately after import.

For algorithms with custom logic (KDF, salted, variable params), implement the `HashAlgorithm` interface directly and call `register()` from `src/core/registry.ts`.

## Pi Extension

@agntn/hashes ships with a Pi agent extension that provides four tools:

- **`hash_compute`** — compute hash digest with any algorithm
- **`hash_hmac`** — compute HMAC with keyed algorithms
- **`hash_verify`** — verify input against expected digest
- **`hash_algorithms`** — list available algorithms with metadata

The extension auto-loads via the `pi.extensions` field in `package.json`.

## Architecture

```
src/
├── core/
│   ├── types.ts        — HashAlgorithm, HashResult, HashOptions interfaces
│   ├── registry.ts     — self-registering factory map (register/create/algorithms/has)
│   ├── resolve.ts      — name normalization + algorithm lookup
│   ├── providers.ts    — builtinAlgorithms list (type-safe)
│   └── errors.ts       — HashError hierarchy
├── algorithms/
│   ├── index.ts        — imports all algorithms (triggers registration)
│   ├── noble-algo.ts   — generic factory for @noble/hashes-backed algorithms
│   ├── noble-helper.ts — encoding/decoding utilities
│   └── *.ts            — individual algorithm implementations
├── commands/
│   ├── hash.ts         — `hashes hash` command
│   ├── hmac.ts         — `hashes hmac` command
│   ├── verify.ts       — `hashes verify` command
│   ├── algorithms.ts   — `hashes algorithms` command
│   └── info.ts         — `hashes info` command
├── cli.ts              — CLI entry point (citty)
├── cli-args.ts         — arg normalization (shorthand support)
├── index.ts            — library entry point
└── version.ts          — version constant
```

## Development

```bash
pnpm dev          # stub build (watch mode)
pnpm build        # production build
pnpm test         # vitest watch
pnpm test:run     # vitest single run
pnpm typecheck    # tsc --noEmit
```

## License

ISC
