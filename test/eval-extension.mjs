#!/usr/bin/env node
// @agntn/hashes Pi extension eval — subprocess smoke test.
// Tests: library load, algorithm registry, hash/hmac/verify, extension structure, error handling.
//
// Run: node --import tsx test/eval-extension.mjs

import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import path from "node:path";

const ROOT = path.resolve(import.meta.dirname, "..");
const EXT_PATH = path.join(ROOT, "packages", "pi", "extensions", "hashes.ts");

let passed = 0;
let failed = 0;

function ok(name, cond, detail = "") {
  if (cond) {
    console.log(`  PASS  ${name}${detail ? `  (${detail})` : ""}`);
    passed++;
  } else {
    console.log(`  FAIL  ${name}${detail ? `  (${detail})` : ""}`);
    failed++;
  }
}

// 1. Extension file parses (TypeScript syntax check)
const parse = spawnSync("node", ["--experimental-strip-types", "--check", EXT_PATH], {
  encoding: "utf8",
  cwd: ROOT,
});
ok("extension .ts parses", parse.status === 0, parse.stderr.trim().slice(0, 200));

// 2. Library loads and all algorithms register
const lib = await import(path.join(ROOT, "src", "index.ts"));
const names = lib.algorithms();
ok("algorithms() returns >= 16 algorithms", names.length >= 16, `got ${names.length}`);
ok("has('sha256')", lib.has("sha256"));
ok("has('blake3')", lib.has("blake3"));
ok("has('crc32')", lib.has("crc32"));
ok("has('scrypt')", lib.has("scrypt"));
ok("has('pbkdf2')", lib.has("pbkdf2"));
ok("has('xxhash')", lib.has("xxhash"));
ok("has('fnv1a')", lib.has("fnv1a"));
ok("has('nonexistent') === false", !lib.has("nonexistent"));

// 3. Known test vectors
{
  const sha256 = lib.create("sha256");
  const r = sha256.hash("");
  ok("sha256('') = e3b0c4...", r.digest === "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
  const r2 = sha256.hash("abc");
  ok("sha256('abc') = ba7816...", r2.digest === "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
}

{
  const md5 = lib.create("md5");
  const r = md5.hash("");
  ok("md5('') = d41d8c...", r.digest === "d41d8cd98f00b204e9800998ecf8427e");
}

{
  const sha1 = lib.create("sha1");
  const r = sha1.hash("abc");
  ok("sha1('abc') = a9993e...", r.digest === "a9993e364706816aba3e25717850c26c9cd0d89d");
}

// 4. HMAC
{
  const sha256 = lib.create("sha256");
  const r = sha256.hash("hello", { key: "secret" });
  ok("sha256 HMAC: operation='hmac'", r.operation === "hmac");
  ok("sha256 HMAC: 64 hex chars", /^[a-f0-9]{64}$/.test(r.digest));
}

// 5. Non-crypto algorithms
{
  const crc32 = lib.create("crc32");
  const r = crc32.hash("hello");
  ok("crc32('hello') = 3610a686", r.digest === "3610a686");
  ok("crc32 digestLength = 4", r.digestLength === 4);
}

{
  const fnv = lib.create("fnv1a");
  const r = fnv.hash("hello");
  ok("fnv1a('hello') = 16 hex chars", /^[a-f0-9]{16}$/.test(r.digest));
}

{
  const xx = lib.create("xxhash");
  const r = xx.hash("hello");
  ok("xxhash('hello') = 16 hex chars", /^[a-f0-9]{16}$/.test(r.digest));
}

// 6. Password KDFs
{
  const scrypt = lib.create("scrypt");
  const salt = "deadbeef00000000deadbeef00000000deadbeef00000000deadbeef00000000";
  const r1 = scrypt.hash("test", { salt });
  const r2 = scrypt.hash("test", { salt });
  ok("scrypt deterministic with same salt", r1.digest === r2.digest);
  ok("scrypt output = 128 hex chars (64 bytes)", /^[a-f0-9]{128}$/.test(r1.digest));
}

{
  const pbkdf2 = lib.create("pbkdf2");
  const salt = "deadbeef00000000deadbeef00000000deadbeef00000000deadbeef00000000";
  const r1 = pbkdf2.hash("test", { salt, iterations: 100000 });
  const r2 = pbkdf2.hash("test", { salt, iterations: 100000 });
  ok("pbkdf2 deterministic with same salt+iterations", r1.digest === r2.digest);
  ok("pbkdf2 output = 128 hex chars (64 bytes)", /^[a-f0-9]{128}$/.test(r1.digest));
}

// 7. Encoding options
{
  const sha256 = lib.create("sha256");
  const hex = sha256.hash("test", { encoding: "hex" });
  const b64 = sha256.hash("test", { encoding: "base64" });
  const b64url = sha256.hash("test", { encoding: "base64url" });
  const bin = sha256.hash("test", { encoding: "binary" });
  ok("hex encoding = 64 chars", hex.digest.length === 64);
  ok("base64 encoding = 44 chars", b64.digest.length === 44);
  ok("base64url encoding has no padding", !b64url.digest.includes("="));
  ok("binary encoding returns Uint8Array", bin.digest instanceof Uint8Array);
}

// 8. resolveAlgorithm normalization
{
  const a = lib.resolveAlgorithm("SHA256");
  ok("resolveAlgorithm('SHA256') → sha256", a.name() === "sha256");
  const b = lib.resolveAlgorithm("sha3_256");
  ok("resolveAlgorithm('sha3_256') → sha3-256", b.name() === "sha3-256");
}

// 9. Error handling
{
  try {
    lib.resolveAlgorithm("nonexistent");
    ok("resolveAlgorithm('nonexistent') throws", false);
  } catch {
    ok("resolveAlgorithm('nonexistent') throws", true);
  }
}

{
  try {
    lib.create("scrypt").hash("test", { N: 3 });
    ok("scrypt with non-power-of-2 N throws", false);
  } catch {
    ok("scrypt with non-power-of-2 N throws", true);
  }
}

// 10. Algorithm info completeness
{
  let allValid = true;
  for (const name of names) {
    const algo = lib.create(name);
    const info = algo.info();
    if (!info.name || !info.label || !info.description || !info.family) {
      allValid = false;
      break;
    }
  }
  ok("all algorithms have complete info (name, label, description, family)", allValid);
}

// 11. Extension file structure
{
  const extSrc = readFileSync(EXT_PATH, "utf8");
  ok("extension registers hash_compute tool", /name:\s*['"]hash_compute['"]/.test(extSrc));
  ok("extension registers hash_hmac tool", /name:\s*['"]hash_hmac['"]/.test(extSrc));
  ok("extension registers hash_verify tool", /name:\s*['"]hash_verify['"]/.test(extSrc));
  ok("extension registers hash_algorithms tool", /name:\s*['"]hash_algorithms['"]/.test(extSrc));
  ok("extension uses ExtensionAPI import", /import.*ExtensionAPI.*from.*pi-coding-agent/.test(extSrc));
  ok("extension uses Type.Object from typebox", /Type\.Object/.test(extSrc));
  ok("extension uses pi.registerTool", /pi\.registerTool/.test(extSrc));
  ok("extension lazy-loads @agntn/hashes", /await import\(['"]@agntn\/hashes['"]\)/.test(extSrc));
  ok("extension uses resolveAlgorithm from lib", /lib\.resolveAlgorithm/.test(extSrc));
}

// 12. BLAKE3 info check (hmac: false)
{
  const blake3 = lib.create("blake3");
  const info = blake3.info();
  ok("blake3 hmac=false", info.hmac === false);
  ok("blake3 info has no key option", !info.options.some((o) => o.name === "key"));
}

// 13. Tool execution via mock Pi
{
  const tools = {};
  const fakePi = { registerTool(def) { tools[def.name] = def; } };
  const ext = await import(path.join(ROOT, "packages", "pi", "extensions", "hashes.ts"));
  ext.default(fakePi);
  ok("mock Pi: 4 tools registered", Object.keys(tools).length === 4);

  // hash_compute
  const r1 = await tools.hash_compute.execute("tc1", { algorithm: "sha256", input: "hello" });
  ok("hash_compute sha256 hello → 2cf24d...", r1.content[0].text === "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824");
  ok("hash_compute details", r1.details.algorithm === "sha256" && r1.details.operation === "hash");

  // hash_hmac
  const r2 = await tools.hash_hmac.execute("tc2", { algorithm: "sha256", input: "data", key: "secret" });
  ok("hash_hmac returns hmac operation", r2.details.operation === "hmac");
  ok("hash_hmac returns 64 hex chars", /^[a-f0-9]{64}$/.test(r2.content[0].text));

  // hash_verify match
  const r3 = await tools.hash_verify.execute("tc3", { algorithm: "sha256", input: "abc", expected: "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" });
  ok("hash_verify match → ✓ MATCH", r3.content[0].text.includes("MATCH") && r3.details.match === true);

  // hash_verify mismatch
  const r4 = await tools.hash_verify.execute("tc4", { algorithm: "sha256", input: "abc", expected: "0000000000000000000000000000000000000000000000000000000000000000" });
  ok("hash_verify mismatch → ✗ MISMATCH", r4.content[0].text.includes("MISMATCH") && r4.details.match === false);

  // hash_algorithms
  const r5 = await tools.hash_algorithms.execute("tc5", {});
  ok("hash_algorithms → 16 lines", r5.content[0].text.split("\n").length === 16);

  // hash_algorithms with filter
  const r6 = await tools.hash_algorithms.execute("tc6", { family: "legacy" });
  ok("hash_algorithms legacy → md5+sha1", r6.content[0].text.includes("md5") && r6.content[0].text.includes("sha1"));

  // error handling
  const r7 = await tools.hash_compute.execute("tc7", { algorithm: "nonexistent", input: "test" });
  ok("hash_compute unknown → clean error", r7.content[0].text.includes("Unknown algorithm"));

  // HMAC unsupported algorithm
  const r8 = await tools.hash_hmac.execute("tc8", { algorithm: "blake3", input: "data", key: "secret" });
  ok("hash_hmac blake3 → unsupported error", r8.content[0].text.includes("does not support HMAC"));
}

// Summary
console.log(`\n  ${passed} passed, ${failed} failed`);
process.exit(failed > 0 ? 1 : 0);
