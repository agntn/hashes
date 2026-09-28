# @agntn/hashes - AGENTS.md

Unified hashing algorithm library for agents. TypeScript, ESM, pnpm monorepo.

## Scope

Library + CLI (`hashes`) + Pi extension providing 16 hashing algorithms via self-registering provider pattern. Single-purpose: hash, HMAC, verify, discover. No networking, no server, no state.

## Conventions

- **Language:** TypeScript (strict, ESNext target, ESM modules)
- **Build:** obuild (`pnpm build` → `dist/`)
- **Test:** vitest (`pnpm test:run`)
- **Package manager:** pnpm 10.33.4, Node ≥ 25
- **Dependencies:** `@noble/hashes` (crypto algorithms), `citty` (CLI), `consola` (logging)
- **No `src/` imports in `dist/`** — library entry is `dist/index.mjs`, CLI is `dist/cli.mjs`

## Key Files

| Path | Role |
|------|------|
| `src/core/registry.ts` | Self-registering algorithm factory map — single source of truth for `register()`, `create()`, `algorithms()`, `has()` |
| `src/core/types.ts` | `HashAlgorithm` interface, `HashResult`, `HashOptions`, `AlgorithmInfo` — canonical shapes |
| `src/core/resolve.ts` | Name normalization + lookup — algorithm resolution entry point |
| `src/core/providers.ts` | `builtinAlgorithms` const array — type-safe list of all built-in names |
| `src/core/errors.ts` | `HashError` hierarchy — `UnknownAlgorithmError`, `InvalidOptionError`, `MissingOptionError`, `DependencyError` |
| `src/algorithms/noble-algo.ts` | `registerNobleAlgorithm()` — generic factory for @noble/hashes-backed algorithms |
| `src/algorithms/noble-helper.ts` | `toBytes()`, `encodeDigest()`, `nobleHash()`, `nobleHmac()` — shared encoding/hashing utilities |
| `src/algorithms/index.ts` | Imports all algorithm modules (triggers self-registration on import) |
| `src/index.ts` | Library entry — imports algorithms, re-exports core |
| `src/cli.ts` | CLI entry — citty main with subcommands |
| `src/cli-args.ts` | `normalizeMainArgs()` — shorthand: `hashes sha256 "x"` → `hashes hash sha256 "x"` |
| `packages/pi/extensions/hashes.ts` | Pi agent extension — `hash_compute`, `hash_hmac`, `hash_verify`, `hash_algorithms` tools |
| `build.config.ts` | obuild config — two entries: `index.ts` (library) + `cli.ts` (CLI) |

## Adding Algorithms

1. Create `src/algorithms/<name>.ts`
2. For noble-backed: `registerNobleAlgorithm({ ... })` with a `CHash` from `@noble/hashes`
3. For custom (KDF, salted): implement `HashAlgorithm` interface + `register(name, factory)`
4. Add `import './<name>'` to `src/algorithms/index.ts`
5. Add name to `builtinAlgorithms` array in `src/core/providers.ts`
6. Add tests in `test/unit/hashes.test.ts`

## Constraints

- **Node ≥ 25** — uses modern Node APIs
- **ESM only** — no CommonJS, `"type": "module"`
- **Algorithm names are lowercase kebab-case** — `normalizeMainArgs` + `resolveAlgorithm` normalize input
- **No runtime dependencies beyond noble-hashes, citty, consola** — keep bundle lean
- **Binary encoding returns `Uint8Array`** — consumer must handle non-string digest
- **scrypt/pbkdf2 produce variable-length output** — no fixed `digestLength` in `AlgorithmInfo`
- **Self-registering pattern** — algorithms register on import; `import './algorithms/index'` is the activation trigger

## Tests

- `test/unit/hashes.test.ts` — registry, known test vectors (SHA-256, MD5, SHA-1, CRC-32, FNV-1a), HMAC, encoding, scrypt/pbkdf2 determinism, info metadata
- `test/eval-cli.mjs` — CLI evaluation
- `test/eval-extension.mjs` — Pi extension evaluation

## Pi Integration

The extension lives in `packages/pi/extensions/hashes.ts` and is registered via `package.json` → `"pi": { "extensions": [...] }`. It lazy-loads the library at runtime. When developing, it falls back to importing from `src/index.ts` directly.

## Related

Part of the `@agntn` library family (`~/Projekty/agntn`); the closest sibling is `@agntn/ciphers`. Formerly `hashhouse` (`~/Projekty/oritwoen/hashhouse`); the rename is a clean cutover without the old `hh` binary.
