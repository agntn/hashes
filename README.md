# @agntn/hashes

[![npm version](https://npmx.dev/api/registry/badge/version/@agntn/hashes)](https://npmx.dev/package/@agntn/hashes)
[![npm downloads](https://npmx.dev/api/registry/badge/downloads/@agntn/hashes)](https://npmx.dev/package/@agntn/hashes)
[![license](https://npmx.dev/api/registry/badge/license/@agntn/hashes)](https://npmx.dev/package/@agntn/hashes)
[![Ask DeepWiki](https://deepwiki.com/badge.svg)](https://deepwiki.com/agntn/hashes)

#️⃣ Sixteen hash algorithms behind one call. You give it text, you get a digest. Same answer in the terminal, in TypeScript and in an agent.

## Why?

Ask a model for the SHA-256 of a string. It will give you 64 hex characters, very confidently. They will be wrong. Hashing is the one thing a language model can't fake, so it should call something that actually hashes. This is that something.

## ✨ Features

- 🧮 **Sixteen algorithms.** SHA-2, SHA-3, BLAKE2b, BLAKE2s, BLAKE3, RIPEMD-160, MD5, SHA-1, CRC-32, xxHash, FNV-1a, scrypt and PBKDF2.
- 🔑 **HMAC where it exists.** Ten of them take a key. The rest say no instead of pretending.
- 🧂 **KDFs that tell you the salt.** No salt given, a random one is drawn and printed next to the digest. Without it that digest is useless.
- ⚖️ **Verify that respects the encoding.** Hex ignores case. Base64 doesn't, because `A` and `a` are different bytes.
- 📥 **Text or bytes.** Pass `-` and it hashes stdin, so files work too.
- 🔤 **Hex, base64, base64url, raw bytes.** Pick with `-e`.
- 🤖 **Six ways in.** CLI, library, MCP, AI SDK, Pi and OMP. The agent ones share four tools and the code behind them.
- 🧩 **Bring your own.** Extend `NobleHash` with any `@noble/hashes` function and `register()` the class.

## 📦 Install

```bash
pnpm add @agntn/hashes
```

Node.js 24 or newer. No network, no keys, no config.

## 🚀 First call

```bash
npx @agntn/hashes sha256 "hello world"
```

```
b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9
```

The first word is the algorithm. Only the digest goes to stdout, so it pipes. For the bare `hashes` below, `pnpm add -g @agntn/hashes` once.

A KDF is more talkative:

```bash
hashes scrypt "correct horse battery staple"
```

```
N 16384, r 8, p 1, keyLength 64, salt 31f4aa33e6346bfa6d576a5dce9eec1c0d6c8e959271d03c2f489a71ac52453b
bc010c96df4510eef56ce1a1fc1d140ee276b92d30a31e2ca2e065f6dac8977c9c1bd5d20951e54fbd5b4474984c0f45f5adbe8c7b18daeeacbef09dc330a902
```

The first line is stderr. Keep the salt, `--salt` takes it back. Run it again without one and you get a different digest. Salts are supposed to do that.

And verify, twice:

```bash
hashes verify sha256 abc "ungWv48Bz+pBQUDeXa4iI7ADYaOWF3qctBD/YfIAFa0=" -e base64
hashes verify sha256 abc "ungwv48bz+pbqudexa4ii7adyaowf3qctbd/yfiafa0=" -e base64
```

```
MATCH sha256 ungWv48Bz+pBQUDeXa4iI7ADYaOWF3qctBD/YfIAFa0=
MISMATCH sha256
  expected ungwv48bz+pbqudexa4ii7adyaowf3qctbd/yfiafa0=
  actual   ungWv48Bz+pBQUDeXa4iI7ADYaOWF3qctBD/YfIAFa0=
```

Same letters, other bytes. The second one exits with 1.

### Commands

| Command      | What it does                                   | Example                                                    |
| ------------ | ---------------------------------------------- | ---------------------------------------------------------- |
| `hash`       | Digest of text, or of stdin with `-`           | `hashes hash blake3 - < file.bin`                          |
| `hmac`       | Keyed digest                                   | `hashes hmac sha256 "message" "secret"`                    |
| `verify`     | Compare with an expected digest, exit 1 if not | `hashes verify md5 hello 5d41402abc4b2a76b9719d911017c592` |
| `algorithms` | The list, `-f` keeps one family                | `hashes algorithms -f password`                            |
| `info`       | One algorithm with its options                 | `hashes info pbkdf2`                                       |
| `mcp`        | The MCP server on stdio                        | `hashes mcp`                                               |

`hash` is the default, so `hashes md5 hello` works. Flags per command: `hashes <command> --help`.

## 🧠 Library

```ts
import { create, resolveAlgorithm, digestMatches } from "@agntn/hashes";

create("sha256").hash("abc").digest; // "ba7816bf8f01cfea..."
create("sha256").hash("message", { key: "secret" }).operation; // "hmac"

const blake3 = resolveAlgorithm("BLAKE3");
blake3.hash(new Uint8Array([1, 2, 3]), { encoding: "base64" });

const result = create("md5").hash("hello");
digestMatches(result, "5D41402ABC4B2A76B9719D911017C592"); // true
```

That's most of it. `create()` wants the exact name. `resolveAlgorithm()` forgives case, spaces and underscores, so `SHA3_256` finds `sha3-256`. Every result has the digest, its length and the options it depends on. Something wrong? It's a `HashError`, and the message names the option. The types in [`src/core/types.ts`](./src/core/types.ts) are the rest.

## 🗂️ Algorithms

| Family            | Algorithms                                                                      | HMAC                 |
| ----------------- | ------------------------------------------------------------------------------- | -------------------- |
| cryptographic     | sha256, sha384, sha512, sha3-256, sha3-512, blake2b, blake2s, blake3, ripemd160 | all but blake3       |
| legacy            | md5, sha1                                                                       | yes                  |
| non-cryptographic | crc32, xxhash, fnv1a                                                            | no                   |
| password          | scrypt, pbkdf2                                                                  | no, they take a salt |

MD5 and SHA-1 are broken for security. They're here for checksums and old systems. `hashes info <name>` has the security note for each.

## 🤖 Agents

```bash
pi install npm:@agntn/hashes
omp install @agntn/hashes
```

```json
{
  "mcpServers": {
    "hashes": { "command": "npx", "args": ["-y", "@agntn/hashes", "mcp"] }
  }
}
```

Four tools: `hash_compute`, `hash_hmac`, `hash_verify` and `hash_algorithms`. Same four in MCP, Pi, OMP and the AI SDK (`@agntn/hashes/ai`). A misspelled argument is an error, not silently ignored. A model that isn't sure calls `hash_algorithms` first.

## 🚫 What this does not do

Password storage for your app. scrypt and PBKDF2 are here so you can reproduce and check a digest, not to run your login. Signing and wallet keys live in [@agntn/keys](https://github.com/agntn/keys), ciphers in [@agntn/ciphers](https://github.com/agntn/ciphers).

## 🧩 Adding an algorithm

Want a seventeenth? Keccak-256 is one small class:

```ts
import { keccak_256 } from "@noble/hashes/sha3.js";
import { NobleHash, register, create } from "@agntn/hashes";

class Keccak256 extends NobleHash {
  static readonly key = "keccak256";
  protected readonly hashFn = keccak_256;
  protected readonly about = {
    label: "Keccak-256",
    description: "Ethereum's hash",
    family: "cryptographic",
    digestLength: 32,
  } as const;
}

register(Keccak256);
create("keccak256").hash("").digest; // "c5d2460186f7233c..."
```

Not a noble function? Extend `Hash` and write `info()` and `hash()` yourself. New built-ins live in `src/algorithms/`. Their test vectors come from OpenSSL or a spec, never from this package.

## 🛠️ Development

```bash
pnpm install
pnpm dev          # vp pack --watch
pnpm lint         # build, then vp lint and vp fmt --check
pnpm typecheck    # tsc over the library, the extensions and the tests
pnpm test         # vp test run
pnpm build        # vp pack
```

## 💛 Thanks

Built with help from two programs that give open source maintainers free access, [Claude for Open Source](https://claude.com/contact-sales/claude-for-oss) and [Codex for Open Source](https://developers.openai.com/community/codex-for-oss). Thanks for that <3

## 📄 License

[MIT](./LICENSE)
