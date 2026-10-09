# Changelog


## v0.7.0

[compare changes](https://github.com/agntn/hashes/compare/v0.6.7...v0.7.0)

### 🚀 Enhancements

- Add MCP server description and icons ([#166](https://github.com/agntn/hashes/pull/166))
- Export the Keccak-f[1600] permutation ([#169](https://github.com/agntn/hashes/pull/169))
- ⚠️  Hash a list of inputs in one call ([#172](https://github.com/agntn/hashes/pull/172))
- ⚠️  Let hash() take a list too ([#175](https://github.com/agntn/hashes/pull/175))
- ⚠️  Search several digests in one pass ([#176](https://github.com/agntn/hashes/pull/176))
- **cli:** Hash several inputs in one call ([#177](https://github.com/agntn/hashes/pull/177))
- Build /mcp with toToolkitTools ([#183](https://github.com/agntn/hashes/pull/183))
- Add a Kdf base class ([#184](https://github.com/agntn/hashes/pull/184))

### 🔥 Performance

- Slice CRC-24 and CRC-16 like the rest ([#171](https://github.com/agntn/hashes/pull/171))

### 🩹 Fixes

- **docs:** Give previews their own database ([#170](https://github.com/agntn/hashes/pull/170))
- Stop shipping broken source maps ([#181](https://github.com/agntn/hashes/pull/181))
- Hash BLAKE2b on big-endian hosts ([#182](https://github.com/agntn/hashes/pull/182))
- Refuse an unknown output encoding ([#186](https://github.com/agntn/hashes/pull/186))

### 💅 Refactors

- ⚠️  Build the CLI with runCli ([#167](https://github.com/agntn/hashes/pull/167))

#### ⚠️ Breaking Changes

- ⚠️  Hash a list of inputs in one call ([#172](https://github.com/agntn/hashes/pull/172))
- ⚠️  Let hash() take a list too ([#175](https://github.com/agntn/hashes/pull/175))
- ⚠️  Search several digests in one pass ([#176](https://github.com/agntn/hashes/pull/176))
- ⚠️  Build the CLI with runCli ([#167](https://github.com/agntn/hashes/pull/167))

### ❤️ Contributors

- Ori ([@oritwoen](https://github.com/oritwoen))
- Aeitwoen ([@aeitwoen](https://github.com/aeitwoen))

## v0.6.7

[compare changes](https://github.com/agntn/hashes/compare/v0.6.6...v0.6.7)

### 🚀 Enhancements

- Run hashes_digest_search in the playground ([#159](https://github.com/agntn/hashes/pull/159))

### 🩹 Fixes

- **docs:** Restore the "every" menu options ([#162](https://github.com/agntn/hashes/pull/162))
- **docs:** Put -- before dashed playground input ([#163](https://github.com/agntn/hashes/pull/163))
- Let hashes install next to Pi 1.x ([#164](https://github.com/agntn/hashes/pull/164))

### ❤️ Contributors

- Ori ([@oritwoen](https://github.com/oritwoen))
- Aeitwoen ([@aeitwoen](https://github.com/aeitwoen))

## v0.6.6

[compare changes](https://github.com/agntn/hashes/compare/v0.6.5...v0.6.6)

### 🚀 Enhancements

- Add the CRC-24 that closes PGP armor ([#145](https://github.com/agntn/hashes/pull/145))
- Add SHA-3 hashers you can feed in pieces ([#150](https://github.com/agntn/hashes/pull/150))
- Ship Sha224Hasher without the registry ([#153](https://github.com/agntn/hashes/pull/153))

### 🩹 Fixes

- **docs:** Stop /mcp echoing raw argument names ([#142](https://github.com/agntn/hashes/pull/142))
- **docs:** Stop /mcp choking on a bare call ([#144](https://github.com/agntn/hashes/pull/144))

### 📖 Documentation

- Stop BLAKE3 claiming it's the odd one out ([#154](https://github.com/agntn/hashes/pull/154))

### ❤️ Contributors

- Ori ([@oritwoen](https://github.com/oritwoen))
- Aeitwoen ([@aeitwoen](https://github.com/aeitwoen))

## v0.6.5

[compare changes](https://github.com/agntn/hashes/compare/v0.6.4...v0.6.5)

### 🚀 Enhancements

- Resolve an algorithm by its label ([#131](https://github.com/agntn/hashes/pull/131))
- Search for the words behind a digest ([#128](https://github.com/agntn/hashes/pull/128))
- **docs:** Hash from any MCP client, no install ([#139](https://github.com/agntn/hashes/pull/139))

### 🔥 Performance

- Slice the CRCs and keep Adler-32 in int32 ([#130](https://github.com/agntn/hashes/pull/130))
- Skip the DataView on short input ([#132](https://github.com/agntn/hashes/pull/132))

### 🩹 Fixes

- Refuse a KDF factory that returns no hasher ([#127](https://github.com/agntn/hashes/pull/127))
- **cli:** Refuse options a command doesn't take ([#137](https://github.com/agntn/hashes/pull/137))

### ✅ Tests

- Stop two tests failing at random ([#138](https://github.com/agntn/hashes/pull/138))

### ❤️ Contributors

- Ori ([@oritwoen](https://github.com/oritwoen))
- Aeitwoen ([@aeitwoen](https://github.com/aeitwoen))

## v0.6.4

[compare changes](https://github.com/agntn/hashes/compare/v0.6.3...v0.6.4)

### 🚀 Enhancements

- Read bcrypt strings in identify ([#121](https://github.com/agntn/hashes/pull/121))
- Add the checksums compression formats use ([#124](https://github.com/agntn/hashes/pull/124))

### ❤️ Contributors

- Ori ([@oritwoen](https://github.com/oritwoen))
- Aeitwoen ([@aeitwoen](https://github.com/aeitwoen))

## v0.6.3

[compare changes](https://github.com/agntn/hashes/compare/v0.6.2...v0.6.3)

### 🚀 Enhancements

- Hash passwords with bcrypt ([#118](https://github.com/agntn/hashes/pull/118))

### 🩹 Fixes

- **docs:** Keep a typed xxHash seed exact ([#115](https://github.com/agntn/hashes/pull/115))
- **docs:** Add vue-tsc for the .vue type check ([#117](https://github.com/agntn/hashes/pull/117))

### 📖 Documentation

- Point base encodings at @agntn/encodings ([#114](https://github.com/agntn/hashes/pull/114))

### ❤️ Contributors

- Ori ([@oritwoen](https://github.com/oritwoen))
- Aeitwoen ([@aeitwoen](https://github.com/aeitwoen))

## v0.6.2

[compare changes](https://github.com/agntn/hashes/compare/v0.6.1...v0.6.2)

### 🚀 Enhancements

- Add length extension for Merkle-Damgard hashes ([#110](https://github.com/agntn/hashes/pull/110))
- Identify a hash by its prefix or length ([#111](https://github.com/agntn/hashes/pull/111))
- **docs:** Add extend and identify to playground ([#112](https://github.com/agntn/hashes/pull/112))

### ❤️ Contributors

- Aeitwoen ([@aeitwoen](https://github.com/aeitwoen))

## v0.6.1

[compare changes](https://github.com/agntn/hashes/compare/v0.6.0...v0.6.1)

### 🚀 Enhancements

- Expose scrypt as a byte function ([#97](https://github.com/agntn/hashes/pull/97))
- Add Argon2 ([#102](https://github.com/agntn/hashes/pull/102))
- Fill in the SHA-2, MD4 and RIPEMD gaps ([#103](https://github.com/agntn/hashes/pull/103))

### 🩹 Fixes

- **tools:** List the options the tools take ([#93](https://github.com/agntn/hashes/pull/93))

### ✅ Tests

- Check the README algorithm counts ([#105](https://github.com/agntn/hashes/pull/105))

### ❤️ Contributors

- Aeitwoen ([@aeitwoen](https://github.com/aeitwoen))
- Ori ([@oritwoen](https://github.com/oritwoen))

## v0.6.0

[compare changes](https://github.com/agntn/hashes/compare/v0.5.0...v0.6.0)

### 🚀 Enhancements

- Add byte function subpaths ([#77](https://github.com/agntn/hashes/pull/77))
- Hash many rounds in one call ([#78](https://github.com/agntn/hashes/pull/78))
- Derive keys with HKDF ([#79](https://github.com/agntn/hashes/pull/79))
- Add OpenSSL EVP_BytesToKey ([#82](https://github.com/agntn/hashes/pull/82))
- Export evpBytesToKey from its own entry ([#85](https://github.com/agntn/hashes/pull/85))

### 🔥 Performance

- Drop BigInt from XXH64 ([#89](https://github.com/agntn/hashes/pull/89))

### 🩹 Fixes

- **tools:** Let scrypt fill the 256 MiB limit ([#72](https://github.com/agntn/hashes/pull/72))
- Ask a registered KDF for its salt ([#81](https://github.com/agntn/hashes/pull/81))
- **release:** Test the fresh build ([#88](https://github.com/agntn/hashes/pull/88))

### 💅 Refactors

- **tools:** ⚠️  Adopt `@agntn/tools` ([#86](https://github.com/agntn/hashes/pull/86))

### 📦 Build

- Skip the release age for `@agntn/*` ([#87](https://github.com/agntn/hashes/pull/87))

#### ⚠️ Breaking Changes

- **tools:** ⚠️  Adopt `@agntn/tools` ([#86](https://github.com/agntn/hashes/pull/86))

### ❤️ Contributors

- Ori
- Aeitwoen

## v0.5.0

[compare changes](https://github.com/agntn/hashes/compare/v0.4.0...v0.5.0)

### 🚀 Enhancements

- Sha1 and md5 as byte functions ([#65](https://github.com/agntn/hashes/pull/65))
- **tools:** ⚠️  Add hashes_ prefix ([#68](https://github.com/agntn/hashes/pull/68))

### 🩹 Fixes

- **omp:** Hash tools run under OMP's TypeBox ([#62](https://github.com/agntn/hashes/pull/62))
- **pi:** Quiet Pi 0.99's typebox warning ([#67](https://github.com/agntn/hashes/pull/67))

### 📖 Documentation

- Say the package is not audited ([#60](https://github.com/agntn/hashes/pull/60))

### 📦 Build

- Switch the bundler to obuild ([#69](https://github.com/agntn/hashes/pull/69))

#### ⚠️ Breaking Changes

- **tools:** ⚠️  Add hashes_ prefix ([#68](https://github.com/agntn/hashes/pull/68))

### ❤️ Contributors

- Aeitwoen ([@aeitwoen](https://github.com/aeitwoen))
- Ori ([@oritwoen](https://github.com/oritwoen))

## v0.4.0

[compare changes](https://github.com/agntn/hashes/compare/v0.3.0...v0.4.0)

### 🚀 Enhancements

- ⚠️  Compute every hash without node:crypto ([#37](https://github.com/agntn/hashes/pull/37))
- Hash hex and base64 input as bytes ([#38](https://github.com/agntn/hashes/pull/38))
- **docs:** Hashes.agntn.dev site and playground ([#39](https://github.com/agntn/hashes/pull/39))
- Binary HMAC keys in hex or base64 ([#43](https://github.com/agntn/hashes/pull/43))
- SHA-0 for old papers and puzzles ([#46](https://github.com/agntn/hashes/pull/46))
- ⚠️  Families by lineage, categories by use ([#47](https://github.com/agntn/hashes/pull/47))
- Byte digests without the registry ([#51](https://github.com/agntn/hashes/pull/51))
- Blake2b takes a personalization ([#54](https://github.com/agntn/hashes/pull/54))

### 🩹 Fixes

- Credit WireGuard to BLAKE2s, not BLAKE2b ([#42](https://github.com/agntn/hashes/pull/42))
- **docs:** Keep playground labels off their values ([#45](https://github.com/agntn/hashes/pull/45))
- Esbuild keeps only the digest it imports ([#53](https://github.com/agntn/hashes/pull/53))
- **docs:** No MCP entries in the page menu ([#55](https://github.com/agntn/hashes/pull/55))
- Verify errors on a digest it cannot decode ([#56](https://github.com/agntn/hashes/pull/56))

### ✅ Tests

- Bundle test packs its own build ([#57](https://github.com/agntn/hashes/pull/57))

#### ⚠️ Breaking Changes

- ⚠️  Compute every hash without node:crypto ([#37](https://github.com/agntn/hashes/pull/37))
- ⚠️  Families by lineage, categories by use ([#47](https://github.com/agntn/hashes/pull/47))

### ❤️ Contributors

- Ori ([@oritwoen](https://github.com/oritwoen))
- Aeitwoen ([@aeitwoen](https://github.com/aeitwoen))

## v0.3.0

[compare changes](https://github.com/agntn/hashes/compare/v0.2.1...v0.3.0)

### 🚀 Enhancements

- ⚠️  Replace shaha with the TypeScript library ([#31](https://github.com/agntn/hashes/pull/31))

#### ⚠️ Breaking Changes

- ⚠️  Replace shaha with the TypeScript library ([#31](https://github.com/agntn/hashes/pull/31))

### ❤️ Contributors

- Ori ([@oritwoen](https://github.com/oritwoen))

