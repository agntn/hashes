# AGENTS.md

Keep AGENTS.md updated with project status.

## Scope

`@agntn/hashes`: hash, HMAC, verify and look up 16 hash and key derivation algorithms. Library, CLI (`hashes`), MCP server, AI SDK tools, Pi and OMP extensions. Local computation only: no network, no state, no keys to configure. Formerly `hashhouse` (`~/Projekty/oritwoen/hashhouse`); the rename was a clean cutover without the old `hh` binary. Signing and wallet keys belong to `@agntn/keys`, ciphers to `@agntn/ciphers`.

## Status

- Aligned with `_template` and moved to Vite+ in the shape of `@agntn/explorers` (#143): `vp pack` builds, `vp lint` and `vp fmt` run the shared `@agntn/ox` policy from `vite.config.ts`, `vp test` runs Vitest 5.
- Algorithms are classes, like ciphers and chains: `Hash` is the base, `NobleHash` wraps a `@noble/hashes` function, `ChecksumHash` a digest computed here, and each class carries a static `key`. The registry is seeded from the class list in `src/algorithms/index.ts` on first use; importing the package mutates nothing, so `sideEffects` is `false`.
- MCP, AI SDK, Pi and OMP share the executors in `src/tool-operations.ts`. MCP and Pi share the TypeBox schemas in `packages/shared/tool-schemas.ts`; OMP restates them with `pi.typebox`, and `test/omp-extension.test.ts` holds both to the same accept/reject answers.
- A local MCP server runs `src/` from the built bin inside a checkout, like `_template`; `HASHES_DIST=1` keeps the bundle. `test/cli.test.ts` proves both modes and each guard.
- Fixed during the refactor, each with a regression test: XXH64 used a wrong `PRIME64_2` and skipped `round()` in the merge and tail steps, so it never produced XXH64 (now identical to the reference `xxhash` on 603 inputs); verify lowercased base64 before comparing; the tools drew a KDF salt and never returned it; pbkdf2 looked `digest` up through `Object.prototype`; a malformed hex salt shrank silently; `--version` hashed the flag; `-` for stdin was documented but not implemented.

## Stack

- **Runtime**: Node.js 26 for development and release; >= 24 supported
- **Language**: TypeScript (strict), relative imports end in `.ts`
- **Build**: `vp pack` (tsdown), chunks under `dist/_chunks/` with stable names
- **Test**: `vp test` (Vitest 5 bundled with vite-plus 1.0.0), APIs from `vite-plus/test`
- **Lint and format**: `vp lint` and `vp fmt` with `@agntn/ox`, type-aware through `oxlint-tsgolint`
- **Typecheck**: `tsc` (TypeScript 7) for the library, then the extensions and the tests after a build
- **Hashing**: `@noble/hashes`; CRC-32, XXH64 and FNV-1a are plain TypeScript
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
src/core/                - Hash, NobleHash, ChecksumHash, types, errors, registry, name resolution, digest helpers, verify
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

1. Create `src/algorithms/<name>.ts` with a class and a static `key`: extend `NobleHash` for a `@noble/hashes` function, `ChecksumHash` for a fixed-length digest computed here, `Hash` for anything else. A KDF declares `SALT_OPTION` in `info()`, which is what makes the tools take and require a salt.
2. Add the class to `builtins` in `src/algorithms/index.ts` and its key to `builtinAlgorithms` in `src/core/algorithms.ts`, in the same position.
3. Update `BUILTIN_ALGORITHMS` (and `HMAC_ALGORITHMS` when it has HMAC) in `packages/shared/tool-contract.ts`.
4. Test it against a vector from outside this package: `node:crypto`, `node:zlib`, a reference library or the spec.

`test/index.test.ts` fails when the files, `builtins` and `builtinAlgorithms` disagree; `test/mcp.test.ts` fails when the tool contract lists differ from the registry.

## Conventions

- ESM only; emitted runtime files are `.mjs`, declarations `.d.mts`.
- No `as any`, `@ts-ignore`, or `@ts-expect-error`.
- Every bound a tool schema declares is enforced again in the executor, and every tool argument table in `TOOL_ARGUMENTS` matches its schema keys.
- Tool schemas are closed (`additionalProperties: false`); an undeclared key is an error on every surface.
- An MCP client sees only `content`, so every fact a follow-up call needs (a KDF's salt and cost) is in the text.
- The CLI prints the digest alone on stdout; a salted digest's parameters go to stderr.
- `pnpm install` hung in `importing_started` with pnpm 11.26 and the default import method on this machine; `--config.package-import-method=hardlink` works.

## Contributing

- Pull requests and issues use short, freeform descriptions focused on why a change is needed or what went wrong.
