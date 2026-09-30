# AGENTS.md

Keep AGENTS.md updated with project status.

## Scope

`@agntn/hashes`: hash, HMAC, verify and look up 25 hash and key derivation algorithms, including the constructions cryptocurrencies use. Library, CLI (`hashes`), MCP server, AI SDK tools, Pi and OMP extensions. Local computation only: no network, no state, no keys to configure. Formerly `hashhouse` (`~/Projekty/oritwoen/hashhouse`); the rename was a clean cutover without the old `hh` binary. Signing and wallet keys belong to `@agntn/keys`, ciphers to `@agntn/ciphers`.

## Status

- `docs/` is the Docus site for hashes.agntn.dev, on the agntn instrument grammar and built from the ciphers site: landing with a live avalanche panel, a guide, one page per algorithm, and a playground that runs the tool executors in the browser. It bundles `../src` through an alias, so a deploy needs no root install; `docs/AGENTS.md` has the rules.
- Aligned with `_template` and moved to Vite+ in the shape of `@agntn/explorers` (#143): `vp lint` and `vp fmt` run the shared `@agntn/ox` policy from `vite.config.ts`, `vp test` runs Vitest 5. The build went back to obuild (#61), like `@agntn/puzzles` and `@agntn/keys`: same files and exports as `vp pack`, a faster build and less JS, since obuild minifies the typebox it inlines and drops the `//#region` markers.
- Algorithms are classes, like ciphers and chains: `Hash` is the base, `FixedHash` a fixed-length digest, `BlockHash` a `FixedHash` built on an incremental `Hasher` with HMAC over its blocks, and each class carries a static `key`. The registry is seeded from the class list in `src/algorithms/index.ts` on first use; importing the package mutates nothing, so `sideEffects` is `false`.
- The digests other libraries need are also plain byte functions exported from the root (#49): `sha256`, `sha512`, `ripemd160`, `hash160`, `hash256`, `keccak256`, `sha3_256`, `blake256`, `blake2b(data, outputLength, personalization?)`, `crc32`, `crc16Xmodem`, `sha1`, `md5`, plus `hmac` and `pbkdf2` over `Sha256Hasher`, `Sha512Hasher`, `Ripemd160Hasher` and `Blake2bHasher`. They live in `src/core/` and the algorithm classes call them. Each refuses anything but a `Uint8Array`, and so does `update()` on every hasher. The KDF, BLAKE2b and SHA-512 lengths are checked too, since these skip the options layer. Importing one leaves the registry out of a bundle: Rolldown takes `sha256` alone at about 9 kB against 68 kB through `create()`, and esbuild, which Wrangler uses, at about 3 kB. The root entry pulls the registry's chunk, so esbuild keeps any module-level call, `new` or template literal it cannot prove pure (#52): put each behind `/* @__PURE__ */`, directly or through a builder, and move a check that throws into the code that needs it. `test/bundle.test.ts` packs the current source into a temporary directory, never the checkout's `dist`, bundles seven byte functions from it with esbuild and fails when one drags the rest in.
- Plain Node can't tree-shake, so each byte function file also has its own entry (#73): `@agntn/hashes/sha1`, `md5`, `sha2`, `ripemd160`, `keccak`, `blake2b`, `blake256`, `crc` and `hmac`, thin re-exports in `src/<name>.ts`. `sha1` from its entry loads in 1.8 ms against 4.5 ms from the root. Each chunk Node loads costs about 0.35 ms whatever its size, so the small digests, `errors.ts` and `hasher.ts` share `_chunks/digests.mjs` (`smallDigests` in `build.config.ts`), and only BLAKE2b, BLAKE-256 and the Keccak sponge get their own; one chunk per module had cost the root import 3.5 ms. A new byte function file goes into `byteEntries`, `exports`, the table in `test/index.test.ts` and the load graph in `test/bundle.test.ts`, which fails when a subpath loads anything beyond its chunks.
- The tools are `hashes_compute`, `hashes_hmac_compute`, `hashes_verify` and `hashes_algorithms`, named after the package like the rest of `@agntn`, object before verb (#63). The `hash_` names went without an alias; the TypeScript exports (`hashCompute`, `hashComputeTool`, `hashComputeSchema`) kept theirs.
- MCP, AI SDK, Pi and OMP share the executors in `src/tool-operations.ts`. MCP and Pi share the TypeBox schemas in `packages/shared/tool-schemas.ts`; OMP restates them with `pi.typebox`, and `test/omp-extension.test.ts` holds both to the same accept/reject answers. The executors import the schemas only as types, since OMP's TypeBox shim has no `.properties` (#58); `test/omp-typebox.test.ts` runs the extension under it.
- `typebox` is an optional peer with the `"*"` range Pi 0.99 asks for, since Pi warns on every load of a package that lists it in `dependencies` (#59); the exact pin sits in `devDependencies`. The hosts hand the extensions their own copy, and obuild inlines one into `dist` for the CLI and the MCP server, declarations included, with its license in `dist/THIRD-PARTY-LICENSES.md`. obuild keeps a peer external, so the `rolldownConfig` hook in `build.config.ts` drops typebox from that list. `test/bundle.test.ts` fails when `dependencies` lists a package Pi supplies or a packed file imports `typebox`.
- Every `FixedHash` takes `rounds` and `chain` (#74), declared once as `ROUND_OPTIONS` in `info()`, so the tools take them as `parameters` and the CLI as flags. Each round after the first hashes the digest's bytes or its lowercase hex, and past one round the result names both. HMAC and the KDFs refuse more than one round. A tool call stops at a million (`PARAMETER_LIMITS`), about 5 s for SHA3-512 in hex.
- Tools and CLI read the input as utf8 (the default), hex or base64 (`inputEncoding`, `--input-encoding`), so `hash160` of a public key hashes its bytes, not the characters that spell it. `hashes_hmac_compute` and `hmac` read the key the same way (`keyEncoding`, `--key-encoding`). `decodeInput` in `src/core/digest.ts` decodes both with the same strict decoder as a salt. An expected digest that is not valid in its encoding, a `0x` prefix included, is an error in `hashes_verify` and `hashes verify` (`assertExpected` in `src/core/verify.ts`), never a MISMATCH; the library's `digestMatches` still answers `false`.
- A local MCP server runs `src/` from the built bin inside a checkout, like `_template`; `HASHES_DIST=1` keeps the bundle. `test/cli.test.ts` proves both modes and each guard.
- No `node:*` import under the library entry (#36): every digest, HMAC, PBKDF2 and scrypt is TypeScript in `src/core/`, the KDF salt comes from `crypto.getRandomValues` and `verify` compares without `timingSafeEqual`. `NodeHash` is gone. A test in `test/index.test.ts` imports `src/index.ts` with `node:*` blocked and runs every algorithm. The CLI and the MCP server keep their Node imports.
- Fixed during the refactor, each with a regression test: XXH64 used a wrong `PRIME64_2` and skipped `round()` in the merge and tail steps, so it never produced XXH64 (now identical to the reference `xxhash` on 603 inputs); BLAKE3 moved off `@noble/hashes` to its own implementation, identical to the reference `blake3` on 285 lengths up to 1 MiB; verify lowercased base64 before comparing; the tools drew a KDF salt and never returned it; pbkdf2 looked `digest` up through `Object.prototype`; a malformed hex salt shrank silently; `--version` hashed the flag; `-` for stdin was documented but not implemented.

## Stack

- **Runtime**: Node.js 26 and newer only (`engines >=26`, CI on 26), where `Uint8Array` has native hex and base64. The library itself needs no Node API.
- **Language**: TypeScript (strict), relative imports end in `.ts`
- **Build**: obuild from `build.config.ts`, one bundle for the five main entries and the byte function subpaths, chunks under `dist/_chunks/` with stable names
- **Test**: `vp test` (Vitest 5 bundled with vite-plus 1.0.0), APIs from `vite-plus/test`
- **Lint and format**: `vp lint` and `vp fmt` with `@agntn/ox`, type-aware through `oxlint-tsgolint`
- **Typecheck**: `tsc` (TypeScript 7) for the library, then the extensions and the tests after a build
- **Hashing**: plain TypeScript for all of it. MD5, SHA-1, SHA-2 and RIPEMD-160 share the Merkle-Damgard buffering in `src/core/hasher.ts`, BLAKE2b and BLAKE2s the BLAKE2 buffering there, SHA-3 and Keccak-256 the sponge in `src/core/keccak.ts`; HMAC and PBKDF2 are in `src/core/hmac.ts`, scrypt in `src/core/scrypt.ts`. Hot loops keep values in locals and typed arrays; a heap number in the loop cost BLAKE2b 2-4x. BLAKE2b adds 64-bit halves with a branchless int32 carry, while SHA-512 sums up to five low halves as one double, about 30% faster in an interleaved run. Measure before choosing. `node:crypto` and `node:zlib` stay in the tests as the outside reference. No hashing dependency.
- **Release**: changelogen
- **Package manager**: pnpm 11

## Scripts

- `pnpm build` - `obuild`
- `pnpm dev` - `obuild --stub`, so `dist` re-exports `src`. The three `hashes mcp` bundle tests in `test/cli.test.ts` fail against a stub on purpose; run them after a real build
- `pnpm lint` - build, then `vp lint` and `vp fmt --check`
- `pnpm fmt` - build, then `vp lint --fix` and `vp fmt` (the autofix workflow runs it on a clean checkout)
- `pnpm typecheck` - library, build, extensions, tests
- `pnpm test` - `vp test run`
- `pnpm release` - test, build, and release

## Structure

```
src/core/                - Hash, FixedHash, BlockHash, the hashers and byte functions, HMAC and the KDFs, types, errors, registry, name resolution, digest helpers, verify
src/algorithms/          - one file per built-in algorithm, plus the builtins list in index.ts
src/commands/            - citty subcommands
src/<name>.ts            - byte function subpaths (sha1, md5, sha2, ripemd160, keccak, blake2b, blake256, crc, hmac)
src/tool-operations.ts   - executors shared by every agent surface
src/mcp.ts, src/ai.ts    - MCP server and AI SDK tools
packages/shared/         - tool contract (bounds, descriptions) and TypeBox schemas, shipped
packages/pi/extensions/  - Pi extension
packages/omp/extensions/ - OMP extension
test/fixtures/           - typed Pi and OMP extension test hosts from _template
docs/                    - the hashes.agntn.dev site, its own pnpm project, outside the root lint
```

## Adding an algorithm

1. Create `src/algorithms/<name>.ts` with a class and a static `key`: extend `BlockHash` for a digest with an HMAC mode (its `Hasher` goes in `src/core/`), `FixedHash` for a fixed-length digest without one, `Hash` for anything else. Its `about` names the `family`, the lineage it comes from (`SHA`, `BLAKE`, `CRC`), and the `category`, what it is fit for (`cryptographic`, `legacy`, `non-cryptographic`, `password`). Nothing under the library entry imports `node:*`. A KDF declares `SALT_OPTION` in `info()`, which is what makes the tools take and require a salt.
2. Add the class to `builtins` in `src/algorithms/index.ts` and its key to `builtinAlgorithms` in `src/core/algorithms.ts`, in the same position.
3. Update `BUILTIN_ALGORITHMS` (and `HMAC_ALGORITHMS` when it has HMAC, `BUILTIN_FAMILIES` when it starts a new family) in `packages/shared/tool-contract.ts`.
4. Test it against a vector from outside this package: `node:crypto`, `node:zlib`, a reference library or the spec.
5. Add its page as `docs/content/2.algorithms/<position>.<name>.md` with `::algorithm-facts{name="<name>"}`, and its icon and blurb to `PRESENTATION` in `docs/app/utils/algorithms.ts`.

`test/index.test.ts` fails when the files, `builtins` and `builtinAlgorithms` disagree; `test/mcp.test.ts` fails when the tool contract lists, families included, differ from the registry; `test/docs.test.ts` fails when an algorithm has no page.

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
