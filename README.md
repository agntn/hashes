# @agntn/hashes

[![npm version](https://npmx.dev/api/registry/badge/version/@agntn/hashes)](https://npmx.dev/package/@agntn/hashes)
[![npm downloads](https://npmx.dev/api/registry/badge/downloads/@agntn/hashes)](https://npmx.dev/package/@agntn/hashes)
[![license](https://npmx.dev/api/registry/badge/license/@agntn/hashes)](https://npmx.dev/package/@agntn/hashes)
[![Ask DeepWiki](https://deepwiki.com/badge.svg)](https://deepwiki.com/agntn/hashes)

#️⃣ Forty-two hash algorithms behind one call. You give it text, you get a digest. Same answer in the terminal, in TypeScript and in an agent.

Docs, and a playground where the library runs in your browser: [hashes.agntn.dev](https://hashes.agntn.dev).

> [!CAUTION]
> **Not audited.** This code has never had a security audit. Do not use it in production, with real funds or with sensitive data. It is meant for agents, puzzles and local experiments only. It comes as is, without warranty of any kind, and the authors are not liable for any loss, as the MIT license states. Anything that matters wants an audited library.

## Why?

Ask a model for the SHA-256 of a string. It will give you 64 hex characters, very confidently. They will be wrong. Hashing is the one thing a language model can't fake, so it should call something that actually hashes. This is that something.

## ✨ Features

- 🧮 **Forty-two algorithms.** SHA-2, SHA-3, BLAKE2, BLAKE3, RIPEMD, MD4, MD5, NTLM, SHA-1, SHA-0, every checksum gzip, bzip2, xz, zlib and lz4 write, the CRC-24 at the foot of PGP armor, xxHash, FNV-1a, scrypt, Argon2, bcrypt, PBKDF2, HKDF and OpenSSL's EVP_BytesToKey.
- 🪙 **The ones chains use.** Keccak-256, HASH160, double SHA-256, BLAKE2b-256 and -224, BLAKE-256, SHA-512Half, SHA-512/256 and CRC-16/XMODEM. Ethereum, Bitcoin, Sui, Cardano, Decred, XRP Ledger, Algorand, Stellar and TON, covered.
- 🔑 **HMAC where it exists.** Nineteen of them take a key. The rest say no instead of pretending.
- 🧂 **KDFs that tell you the salt.** No salt given, scrypt, Argon2 and PBKDF2 draw a random one and print it next to the digest. Without it that digest is useless.
- ⚖️ **Verify that respects the encoding.** Hex ignores case. Base64 doesn't, because `A` and `a` are different bytes.
- ⚡ **Plain TypeScript.** Every algorithm is computed right here. The library imports nothing from `node:*`, and there's no hashing dependency at all.
- 📥 **Text or bytes.** Pass `-` and it hashes stdin, so files work too. Got a public key in hex? `--input-encoding hex` hashes its bytes, not the letters.
- 🔤 **Hex, base64, base64url, raw bytes.** Pick with `-e`.
- 🔁 **Ten thousand rounds, one call.** `--rounds 10000 --chain hex` hashes each digest again. Bytes or hex in between? Puzzles use both, so you pick.
- ✂️ **Length extension.** Got `md5(secret + message)` and the secret's length? `hashes extend` signs a longer message. No secret needed.
- 🔎 **No name on the digest?** `hashes identify` lists what fits its length or its `$2b$` prefix. Argon2, bcrypt, scrypt and PBKDF2 strings come apart into salt, costs and digest.
- 🔀 **Words but no recipe?** `hashes search <digest> <words...>` tries every order, joiner, case, algorithm and round count until one gives the digest. It tells you the total before it starts.
- 🤖 **Six ways in.** CLI, library, MCP, AI SDK, Pi and OMP. The agent ones share the same tools and the code behind them, and the MCP one also runs at [hashes.agntn.dev/mcp](https://hashes.agntn.dev/guide/agents#remote-mcp) with nothing to install.
- 🧩 **Bring your own.** Extend `FixedHash`, or `BlockHash` if you want HMAC too, and `register()` the class.

## 📦 Install

```bash
pnpm add @agntn/hashes
```

Node.js 26 or newer. No network, no keys, no config.

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

| Command      | What it does                                       | Example                                                               |
| ------------ | -------------------------------------------------- | --------------------------------------------------------------------- |
| `hash`       | Digest of text, or of stdin with `-`               | `hashes hash blake3 - < file.bin`                                     |
| `hmac`       | Keyed digest                                       | `hashes hmac sha256 "message" "secret"`                               |
| `verify`     | Compare with an expected digest, exit 1 if not     | `hashes verify md5 hello 5d41402abc4b2a76b9719d911017c592`            |
| `extend`     | Length extension, one line per secret length       | `hashes extend md5 <digest> --message m --suffix x --secret-length 3` |
| `identify`   | Candidates for a hash, by prefix or length         | `hashes identify 5d41402abc4b2a76b9719d911017c592`                    |
| `search`     | The words and the recipe behind a digest           | `hashes search <digest> alpha beta --rounds 2`                        |
| `algorithms` | The list, `-f` keeps one family, `-c` one category | `hashes algorithms -f sha`                                            |
| `info`       | One algorithm with its options                     | `hashes info pbkdf2`                                                  |
| `mcp`        | The MCP server on stdio                            | `hashes mcp`                                                          |

`hash` is the default, so `hashes md5 hello` works. Flags per command: `hashes <command> --help`.

## 🧠 Library

```ts
import { create, resolveAlgorithm, digestMatches } from "@agntn/hashes";

create("sha256").hash("abc").digest; // "ba7816bf8f01cfea..."
create("sha256").hash("message", { key: "secret" }).operation; // "hmac"
create("sha256").hash("abc", { rounds: 2 }).digest; // "4f8b42c22dd3729b...", hash256 by another name

const blake3 = resolveAlgorithm("BLAKE3");
blake3.hash(new Uint8Array([1, 2, 3]), { encoding: "base64" });

const result = create("md5").hash("hello");
digestMatches(result, "5D41402ABC4B2A76B9719D911017C592"); // true
```

That's most of it. `create()` wants the exact name. `resolveAlgorithm()` forgives case and punctuation and takes the label too, so `SHA3_256` finds `sha3-256` and `SHA-256` finds `sha256`. Every result has the digest, its length and the options it depends on. Something wrong? It's a `HashError`, and the message names the option. The types in [`src/core/types.ts`](./src/core/types.ts) are the rest.

Only need bytes in and bytes out? `sha256`, `hash160`, `keccak256` and friends take a `Uint8Array` and return one. No registry comes along. `hmac`, `pbkdf2`, `hkdf` and `evpBytesToKey` run over `Sha512Hasher` and the other hashers. Plain Node doesn't tree-shake, so each group also has its own entry, and `import { sha1 } from "@agntn/hashes/sha1"` starts without the registry. The list is in [the hashing guide](https://hashes.agntn.dev/guide/hashing).

## 🗂️ Algorithms

| Category          | Algorithms                                                                                                                                                                                                     | HMAC                                                          |
| ----------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------- |
| cryptographic     | sha256, sha384, sha512, sha224, sha512-224, sha512-256, sha512-half, sha3-256, sha3-512, keccak256, blake2b, blake2b-256, blake2b-224, blake2s, blake3, blake256, ripemd160, ripemd320, hash160, hash256, hkdf | sha2, sha3, keccak256, blake2b, blake2s, ripemd160, ripemd320 |
| legacy            | md5, md4, ntlm, sha1, sha0, ripemd128, ripemd256                                                                                                                                                               | all but ntlm                                                  |
| non-cryptographic | crc32, crc64, crc24, crc16-xmodem, adler32, xxhash, fnv1a                                                                                                                                                      | no                                                            |
| password          | scrypt, pbkdf2, evp-bytestokey, argon2id, argon2i, argon2d, bcrypt                                                                                                                                             | no, they take a salt                                          |

That's the category, what an algorithm is fit for. Each one also has a family, where it comes from: SHA, Keccak, BLAKE, RIPEMD, MD, CRC, Adler, xxHash, FNV, scrypt, PBKDF, HKDF, OpenSSL, Argon2, bcrypt. So SHA-0 and SHA3-256 share a family and nothing else, and `hashes algorithms -f sha` shows both.

MD4, MD5, NTLM, SHA-1 and SHA-0 are broken for security. They're here for checksums, old systems and old papers. `hashes info <name>` has the security note for each.

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

No Node at all? The docs site serves the same tools over HTTP, plus `list-pages` and `get-page` for reading the guide:

```bash
claude mcp add --transport http hashes https://hashes.agntn.dev/mcp
```

Everything you send there passes through a Cloudflare worker. Fine for test vectors, not for your real password.

The tools: `hashes_compute`, `hashes_hmac_compute`, `hashes_verify`, `hashes_digest_extend`, `hashes_digest_identify`, `hashes_digest_search` and `hashes_algorithms`. The same ones in MCP, Pi, OMP and the AI SDK (`@agntn/hashes/ai`). A misspelled argument is an error, not silently ignored. Bytes go in as hex or base64 with `inputEncoding` and `keyEncoding`, same as the CLI flags. A model that isn't sure calls `hashes_algorithms` first.

## 🚫 What this does not do

Password storage for your app. scrypt, Argon2 and PBKDF2 are here so you can reproduce and check a digest, not to run your login. Signing and wallet keys live in [@agntn/keys](https://github.com/agntn/keys), ciphers in [@agntn/ciphers](https://github.com/agntn/ciphers). Hex and base64 are here for digests only, base58, bech32 and the rest are [@agntn/encodings](https://github.com/agntn/encodings).

## 🧩 Adding an algorithm

Missing one? A fixed-length digest is one small class. On Node you can still borrow it from `node:crypto`:

```ts
import { createHash } from "node:crypto";
import { FixedHash, register, create } from "@agntn/hashes";

class Sha3_384 extends FixedHash {
  static readonly key = "sha3-384";
  protected readonly about = {
    label: "SHA3-384",
    description: "SHA-3 family 384-bit hash",
    family: "SHA",
    category: "cryptographic",
    digestLength: 48,
  } as const;

  protected digest(bytes: Uint8Array): Uint8Array {
    return createHash("sha3-384").update(bytes).digest();
  }
}

register(Sha3_384);
create("sha3-384").hash("abc").digest; // "ec01498288516fc92645..."
```

Want HMAC as well? Extend `BlockHash` and hand it a `Hasher`. Anything else extends `Hash`, and you write `info()` and `hash()` yourself. New built-ins live in `src/algorithms/`. Their test vectors come from OpenSSL, a spec or a reference implementation, never from this package.

## 🛠️ Development

```bash
pnpm install
pnpm --dir docs install   # the /mcp test borrows Zod and the toolkit from here
pnpm dev          # obuild --stub, dist runs straight from src
pnpm lint         # build, then vp lint and vp fmt --check
pnpm typecheck    # tsc over the library, the extensions and the tests
pnpm test         # vp test run
pnpm build        # obuild
```

## 💛 Thanks

Built with help from two programs that give open source maintainers free access, [Claude for Open Source](https://claude.com/contact-sales/claude-for-oss) and [Codex for Open Source](https://developers.openai.com/community/codex-for-oss). Thanks for that <3

## 📄 License

[MIT](./LICENSE)
