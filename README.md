# @agntn/hashes

[![npm version](https://npmx.dev/api/registry/badge/version/@agntn/hashes)](https://npmx.dev/package/@agntn/hashes)
[![npm downloads](https://npmx.dev/api/registry/badge/downloads/@agntn/hashes)](https://npmx.dev/package/@agntn/hashes)
[![license](https://npmx.dev/api/registry/badge/license/@agntn/hashes)](https://npmx.dev/package/@agntn/hashes)
[![Ask DeepWiki](https://deepwiki.com/badge.svg)](https://deepwiki.com/agntn/hashes)

#️⃣ Forty-six hash algorithms for your terminal, TypeScript and agents. Give it text or bytes, get a digest and the options needed to repeat it.

> [!CAUTION]
> **Not audited.** This code has never had a security audit. Do not use it in production, with real funds or with sensitive data. It is meant for agents, puzzles and local experiments only. It comes as is, without warranty of any kind, and the authors are not liable for any loss, as the MIT license states. Anything that matters wants an audited library.

## Why?

A puzzle asks for SHA-256 twice. Twice over bytes, or over the hex from round one? Congratulations, now you have two answers. This package runs either recipe and gives your agent something better than a confident guess.

Docs and a browser playground: [hashes.agntn.dev](https://hashes.agntn.dev).

## 📦 Install

```bash
pnpm add @agntn/hashes
```

Node.js 26 or newer. Local hashing needs no network, API key or config.

## 🚀 First call

```bash
npx @agntn/hashes sha256 "hello world"
```

```text
b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9
```

One input, just the digest on stdout. Ready for a pipe. For the bare `hashes` commands below, install once with `pnpm add -g @agntn/hashes`.

Check a digest too:

```bash
hashes verify sha256 abc "ungWv48Bz+pBQUDeXa4iI7ADYaOWF3qctBD/YfIAFa0=" -e base64
hashes verify sha256 abc "ungwv48bz+pbqudexa4ii7adyaowf3qctbd/yfiafa0=" -e base64
```

```text
MATCH sha256 ungWv48Bz+pBQUDeXa4iI7ADYaOWF3qctBD/YfIAFa0=
MISMATCH sha256
  expected ungwv48bz+pbqudexa4ii7adyaowf3qctbd/yfiafa0=
  actual   ungWv48Bz+pBQUDeXa4iI7ADYaOWF3qctBD/YfIAFa0=
```

Hex ignores case. Base64 doesn't. Same letters, different bytes, and the second command exits with 1. Lowercasing everything isn't cleanup here, it's sabotage.

### Commands

| Command      | What you get                             | Example                                                               |
| ------------ | ---------------------------------------- | --------------------------------------------------------------------- |
| `hash`       | Digest of text or stdin                  | `hashes hash blake3 - < file.bin`                                     |
| `hmac`       | Digest under a key                       | `hashes hmac sha256 "message" "secret"`                               |
| `verify`     | Match or mismatch, exit 1 on mismatch    | `hashes verify md5 hello 5d41402abc4b2a76b9719d911017c592`            |
| `extend`     | Length extension of a known digest       | `hashes extend md5 <digest> --message m --suffix x --secret-length 3` |
| `identify`   | Candidates by prefix or digest length    | `hashes identify 5d41402abc4b2a76b9719d911017c592`                    |
| `search`     | A recipe from your candidate words       | `hashes search 5d41402abc4b2a76b9719d911017c592 hello world`          |
| `algorithms` | Registry, filtered by family or category | `hashes algorithms -f sha`                                            |
| `info`       | One algorithm and its options            | `hashes info pbkdf2`                                                  |
| `mcp`        | MCP server on stdio                      | `hashes mcp`                                                          |

`hash` is optional: `hashes md5 hello` works. Several inputs get a line each. `hmac` and `verify` take the key or expected digest last. Use `hashes <command> --help` for flags, or the [CLI guide](https://hashes.agntn.dev/guide/cli) for encodings, JSON and exit codes.

## ✨ What you can do

- 🧮 **Forty-six algorithms.** Modern digests, old formats, checksums and KDFs. Pick one from the table.
- 🔑 **HMAC where supported.** Twenty-three of them take a key. The others refuse it.
- 🧂 **Reproduce a KDF.** Random salts and costs come back with the result. Keep them, not just the digest.
- 📥 **Hash bytes, not their spelling.** Stdin takes files. `--input-encoding hex` decodes hex before hashing.
- 🔁 **Repeat a hash.** Choose raw bytes or hex between rounds. Yes, those give different answers.
- 🔎 **Investigate a digest.** Identify candidates, search word combinations or try length extension. Identification is a guess, not proof.
- ⚡ **Use plain TypeScript.** The library has no hashing dependencies or `node:*` imports. Byte functions have their own package entries too.
- 🤖 **Give agents the calculator.** CLI, library, MCP, AI SDK, Pi and OMP use the same hashing code.

## 🧠 Library

```ts
import { create, digestMatches } from "@agntn/hashes";

const sha256 = create("sha256");
const result = sha256.hash("abc");
console.log(result.digest);
console.log(sha256.hash("message", { key: "secret" }).operation);
console.log(sha256.hash(["hello", "world"]).length);
console.log(digestMatches(create("md5").hash("hello"), "5D41402ABC4B2A76B9719D911017C592"));
```

```text
ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
hmac
2
true
```

Strings are UTF-8. Already have bytes? Pass a `Uint8Array`. `create()` takes the exact registry name, while `resolveAlgorithm()` accepts labels, case and punctuation. Unsupported encodings throw a `HashError`. A hex string is still text here. Decode it first.

[Hashing and byte imports](https://hashes.agntn.dev/guide/hashing) · [Verify](https://hashes.agntn.dev/guide/verify) · [KDFs and salts](https://hashes.agntn.dev/guide/kdf)

## 🗂️ Algorithms

| Category          | Algorithms                                                                                                                                                                                                                | HMAC                                                                     |
| ----------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------ |
| cryptographic     | sha256, sha384, sha512, sha224, sha512-224, sha512-256, sha512-half, sha3-256, sha3-512, keccak256, blake2b, blake2b-256, blake2b-224, blake2s, blake3, blake256, ripemd160, ripemd320, hash160, hash256, whirlpool, hkdf | sha2, sha3, keccak256, blake2b, blake2s, ripemd160, ripemd320, whirlpool |
| legacy            | md5, md4, md2, ntlm, sha1, sha0, ripemd128, ripemd256, haval, tiger                                                                                                                                                       | all but ntlm                                                             |
| non-cryptographic | crc32, crc64, crc24, crc16-xmodem, adler32, xxhash, fnv1a                                                                                                                                                                 | no                                                                       |
| password          | scrypt, pbkdf2, evp-bytestokey, argon2id, argon2i, argon2d, bcrypt                                                                                                                                                        | no, they take a salt                                                     |

Categories describe use, families describe lineage. `hashes algorithms -f sha` includes SHA-0 and SHA-3. That isn't a security recommendation. MD2, MD4, MD5, NTLM, SHA-1, SHA-0 and HAVAL are broken for security. Check `hashes info <name>` for individual security notes and [algorithm pages](https://hashes.agntn.dev/algorithms) for details.

## 🤖 Agents

```bash
pi install npm:@agntn/hashes
omp install @agntn/hashes
```

For an MCP client:

```json
{
  "mcpServers": {
    "hashes": { "command": "npx", "args": ["-y", "@agntn/hashes", "mcp"] }
  }
}
```

Or skip the local install:

```bash
claude mcp add --transport http hashes https://hashes.agntn.dev/mcp
```

Remote inputs pass through a Cloudflare worker. Use public test vectors, never real passwords. Local MCP, Pi, OMP and `@agntn/hashes/ai` expose seven tools. Batch hashing takes up to 64 inputs per call. No need to make the model ask 64 times.

[Tools, arguments and host setup](https://hashes.agntn.dev/guide/agents)

## 🚫 What this does not do

This is not password storage for your app. The KDFs reproduce test vectors and puzzle recipes, not your login system.

Need signatures or wallets? [@agntn/keys](https://github.com/agntn/keys). Encryption? [@agntn/ciphers](https://github.com/agntn/ciphers). Other binary encodings? [@agntn/encodings](https://github.com/agntn/encodings).

## 🧩 Add your own algorithm

Missing a digest? Extend `FixedHash` and `register()` your class. HMAC uses `BlockHash`, key derivation uses `Kdf`. The [custom algorithm guide](https://hashes.agntn.dev/guide/custom) has working examples, including one backed by `node:crypto`.

## 🛠️ Development

```bash
pnpm install
pnpm dev
pnpm docs
pnpm lint
pnpm typecheck
pnpm test
pnpm build
```

One install and you're set. `docs/` lives in the same workspace, so the site and its MCP test deps come along for free. `dev` stubs `dist` to run from source, `docs` starts the site. `lint` builds, then checks lint and formatting. Tests need a real build. Adding a built-in? Start with [CONTRIBUTING.md](./CONTRIBUTING.md).

## 💛 Thanks

[Claude for Open Source](https://claude.com/contact-sales/claude-for-oss) and [Codex for Open Source](https://developers.openai.com/community/codex-for-oss) give maintainers free access. That helps this package happen. Thanks for that <3

## 📄 License

[MIT](./LICENSE)
