# Contributing

## Setup

Run `pnpm install`, then `pnpm --dir docs install`: `test/docs-mcp.test.ts` borrows Zod and the toolkit from `docs/node_modules`. The `hashes mcp` bundle tests in `test/cli.test.ts` want a real `pnpm build`, not the `pnpm dev` stub.

## Adding an algorithm

1. Create `src/algorithms/<name>.ts` with a class and a static `key`: extend `BlockHash` for a digest with an HMAC mode (its `Hasher` goes in `src/core/`), `FixedHash` for a fixed-length digest without one, `Kdf` for a key derivation function, `Hash` for anything else, whose `hash()` answers a list with `isInputList` like `FixedHash` and `Kdf` do. Its `about` names the `family`, the lineage it comes from (`SHA`, `BLAKE`, `CRC`), and the `category`, what it is fit for (`cryptographic`, `legacy`, `non-cryptographic`, `password`). A KDF with a cost and a `keyLength` sets `floorCosts`, which verify's length check derives at. A KDF that draws a random salt puts `SALT_OPTION` in its `options`; its `random: true` makes verify require one.
2. Add the class to `builtins` in `src/algorithms/index.ts` and its key to `builtinAlgorithms` in `src/core/algorithms.ts`, in the same position.
3. Update `BUILTIN_ALGORITHMS` (and `HMAC_ALGORITHMS` when it has HMAC, `BUILTIN_FAMILIES` when it starts a new family) in `extensions/shared/tool-contract.ts`. A digest PBKDF2 and EVP_BytesToKey take needs a price in `ITERATION_COSTS`.
4. Test it against a vector from outside this package: `node:crypto`, `node:zlib`, a reference library or the spec.
5. Add its page as `docs/content/2.algorithms/<position>.<name>.md` with `::algorithm-facts{name="<name>"}`, and its icon and blurb to `PRESENTATION` in `docs/app/utils/algorithms.ts`.

`test/index.test.ts` fails when the files, `builtins` and `builtinAlgorithms` disagree, `test/mcp.test.ts` when the tool contract differs from the registry or a digest has no price, and `test/docs.test.ts` when an algorithm has no page or the README counts wrong.

A variant is an option of its family, never an algorithm of its own: CRC-32/BZIP2 is `crc32` with `variant: bzip2`. The option lists its values in `choices`, and the byte function takes the same value as an argument.

## Options and tools

- An algorithm's options besides `encoding` and `key` come from one place, `info().options`, checked by `checkedParameters` in `src/core/options.ts`. The CLI turns them into flags and the tools take them as `parameters`.
- Every bound a tool schema declares is enforced again in the executor, every table in `TOOL_ARGUMENTS` matches its schema keys, and schemas are closed.
- Tool calls cap KDF costs in `extensions/shared/tool-contract.ts`; the library leaves them to the caller. A capped parameter starts at 1 unless `ZERO_PARAMETERS` lists it.
- An MCP client sees only `content`, so every fact a follow-up call needs, such as a KDF's salt and cost, is in the text.

## Size and speed

- Nothing under the library entry imports `node:*`; `test/index.test.ts` runs every algorithm with it blocked.
- A new byte function file goes into `byteEntries` in `build.config.ts`, `exports`, the table in `test/index.test.ts` and the load graph in `test/bundle.test.ts`.
- A module-level call, `new` or template literal goes behind `/* @__PURE__ */`, or esbuild keeps it in every bundle.
- Hot loops keep values in locals and typed arrays. Measure before choosing, in an interleaved run.
