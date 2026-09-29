# AGENTS.md

Keep AGENTS.md updated with project status.

## Scope

`@agntn/hashes`: hash, HMAC, verify and look up 24 hash and key derivation algorithms, including the constructions cryptocurrencies use. Library, CLI (`hashes`), MCP server, AI SDK tools, Pi and OMP extensions. Local computation only: no network, no state, no keys to configure. Formerly `hashhouse` (`~/Projekty/oritwoen/hashhouse`); the rename was a clean cutover without the old `hh` binary. Signing and wallet keys belong to `@agntn/keys`, ciphers to `@agntn/ciphers`.

## Status

- Aligned with `_template` and moved to Vite+ in the shape of `@agntn/explorers` (#143): `vp pack` builds, `vp lint` and `vp fmt` run the shared `@agntn/ox` policy from `vite.config.ts`, `vp test` runs Vitest 5.
- Algorithms are classes, like ciphers and chains: `Hash` is the base, `FixedHash` a fixed-length digest, `BlockHash` a `FixedHash` built on an incremental `Hasher` with HMAC over its blocks, and each class carries a static `key`. The registry is seeded from the class list in `src/algorithms/index.ts` on first use; importing the package mutates nothing, so `sideEffects` is `false`.
- MCP, AI SDK, Pi and OMP share the executors in `src/tool-operations.ts`. MCP and Pi share the TypeBox schemas in `packages/shared/tool-schemas.ts`; OMP restates them with `pi.typebox`, and `test/omp-extension.test.ts` holds both to the same accept/reject answers.
- A local MCP server runs `src/` from the built bin inside a checkout, like `_template`; `HASHES_DIST=1` keeps the bundle. `test/cli.test.ts` proves both modes and each guard.
- No `node:*` import under the library entry (#36): every digest, HMAC, PBKDF2 and scrypt is TypeScript in `src/core/`, the KDF salt comes from `crypto.getRandomValues` and `verify` compares without `timingSafeEqual`. `NodeHash` is gone. A test in `test/index.test.ts` imports `src/index.ts` with `node:*` blocked and runs every algorithm. The CLI and the MCP server keep their Node imports.
- Fixed during the refactor, each with a regression test: XXH64 used a wrong `PRIME64_2` and skipped `round()` in the merge and tail steps, so it never produced XXH64 (now identical to the reference `xxhash` on 603 inputs); BLAKE3 moved off `@noble/hashes` to its own implementation, identical to the reference `blake3` on 285 lengths up to 1 MiB; verify lowercased base64 before comparing; the tools drew a KDF salt and never returned it; pbkdf2 looked `digest` up through `Object.prototype`; a malformed hex salt shrank silently; `--version` hashed the flag; `-` for stdin was documented but not implemented.

## Stack

- **Runtime**: Node.js 26 and newer only (`engines >=26`, CI on 26), where `Uint8Array` has native hex and base64. The library itself needs no Node API.
- **Language**: TypeScript (strict), relative imports end in `.ts`
- **Build**: `vp pack` (tsdown), chunks under `dist/_chunks/` with stable names
- **Test**: `vp test` (Vitest 5 bundled with vite-plus 1.0.0), APIs from `vite-plus/test`
- **Lint and format**: `vp lint` and `vp fmt` with `@agntn/ox`, type-aware through `oxlint-tsgolint`
- **Typecheck**: `tsc` (TypeScript 7) for the library, then the extensions and the tests after a build
- **Hashing**: plain TypeScript for all of it. MD5, SHA-1, SHA-2 and RIPEMD-160 share the Merkle-Damgard buffering in `src/core/hasher.ts`, SHA-3 and Keccak-256 the sponge in `src/core/keccak.ts`; HMAC and PBKDF2 are in `src/core/hmac.ts`, scrypt in `src/core/scrypt.ts`. Hot loops keep values in locals and typed arrays; a heap number in the loop cost BLAKE2b 2-4x. BLAKE2b adds 64-bit halves with a branchless int32 carry, while SHA-512 sums up to five low halves as one double, about 30% faster in an interleaved run. Measure before choosing. `node:crypto` and `node:zlib` stay in the tests as the outside reference. No hashing dependency.
- **Release**: changelogen
- **Package manager**: pnpm 11

## Scripts

- `pnpm build` - `vp pack`
- `pnpm dev` - `vp pack --watch`
- `pnpm lint` - build, then `vp lint` and `vp fmt --check`
- `pnpm fmt` - build, then `vp lint --fix` and `vp fmt` (the autofix workflow runs it on a clean checkout)
- `pnpm typecheck` - library, build, extensions, tests
- `pnpm test` - `vp test run`
- `pnpm release` - test, build, and release

## Structure

```
src/core/                - Hash, FixedHash, BlockHash, the hashers, HMAC and the KDFs, types, errors, registry, name resolution, digest helpers, verify
src/algorithms/          - one file per built-in algorithm, plus the builtins list in index.ts
src/commands/            - citty subcommands
src/tool-operations.ts   - executors shared by every agent surface
src/mcp.ts, src/ai.ts    - MCP server and AI SDK tools
packages/shared/         - tool contract (bounds, descriptions) and TypeBox schemas, shipped
packages/pi/extensions/  - Pi extension
packages/omp/extensions/ - OMP extension
test/fixtures/           - typed Pi and OMP extension test hosts from _template
```

## Adding an algorithm

1. Create `src/algorithms/<name>.ts` with a class and a static `key`: extend `BlockHash` for a digest with an HMAC mode (its `Hasher` goes in `src/core/`), `FixedHash` for a fixed-length digest without one, `Hash` for anything else. Nothing under the library entry imports `node:*`. A KDF declares `SALT_OPTION` in `info()`, which is what makes the tools take and require a salt.
2. Add the class to `builtins` in `src/algorithms/index.ts` and its key to `builtinAlgorithms` in `src/core/algorithms.ts`, in the same position.
3. Update `BUILTIN_ALGORITHMS` (and `HMAC_ALGORITHMS` when it has HMAC) in `packages/shared/tool-contract.ts`.
4. Test it against a vector from outside this package: `node:crypto`, `node:zlib`, a reference library or the spec.

`test/index.test.ts` fails when the files, `builtins` and `builtinAlgorithms` disagree; `test/mcp.test.ts` fails when the tool contract lists differ from the registry.

## Conventions

- ESM only; emitted runtime files are `.mjs`, declarations `.d.mts`.
- No `as any`, `@ts-ignore`, or `@ts-expect-error`.
- Every bound a tool schema declares is enforced again in the executor, and every tool argument table in `TOOL_ARGUMENTS` matches its schema keys.
- Tool schemas are closed (`additionalProperties: false`); an undeclared key is an error on every surface.
- An algorithm's options besides `encoding` and `key` (salt, seed, KDF costs) reach every surface from one place: `info().options`, checked by `checkedParameters` in `src/core/options.ts`. The CLI turns them into flags, the tools take them as `parameters`, and a name the algorithm does not declare is an error, never dropped. Tool calls also cap KDF costs (`PARAMETER_LIMITS`, `MAX_SCRYPT_MEMORY`); the library leaves them to the caller. omptype ignores `maxProperties`, so the executor enforces `MAX_PARAMETERS` itself.
- An MCP client sees only `content`, so every fact a follow-up call needs (a KDF's salt and cost) is in the text.
- The CLI prints the digest alone on stdout; a salted digest's parameters go to stderr.
- `pnpm install` hung in `importing_started` with pnpm 11.26 and the default import method on this machine; `--config.package-import-method=hardlink` works.

## Contributing

- Pull requests and issues use short, freeform descriptions focused on why a change is needed or what went wrong.
