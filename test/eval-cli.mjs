#!/usr/bin/env node
// @agntn/hashes CLI eval — subprocess end-to-end test.
// Run: node test/eval-cli.mjs

import { spawnSync } from "node:child_process";
import path from "node:path";

const ROOT = path.resolve(import.meta.dirname, "..");
const CLI = path.join(ROOT, "src", "cli.ts");

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

function run(args, opts = {}) {
  return spawnSync("node", ["--import", "tsx", CLI, ...args], {
    encoding: "utf8",
    cwd: ROOT,
    timeout: 10000,
    ...opts,
  });
}

// 1. Default (no args) → algorithms list
{
  const r = run([]);
  ok("no args → algorithms list", r.status === 0 && r.stdout.includes("SHA-256"));
}

// 2. Hash subcommand
{
  const r = run(["hash", "sha256", "hello"]);
  ok("hash sha256 hello → 64 hex", r.status === 0 && /^[a-f0-9]{64}$/.test(r.stdout.trim()));
}

// 3. Default subcommand (implicit hash)
{
  const r = run(["sha256", "hello"]);
  ok("sha256 hello (implicit hash) → 64 hex", r.status === 0 && /^[a-f0-9]{64}$/.test(r.stdout.trim()));
}

// 4. HMAC
{
  const r = run(["hmac", "sha256", "data", "key"]);
  ok("hmac sha256 data key → 64 hex", r.status === 0 && /^[a-f0-9]{64}$/.test(r.stdout.trim()));
}

// 5. Verify (match)
{
  const r = run(["verify", "sha256", "abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"]);
  ok("verify sha256 abc → MATCH", r.status === 0 && r.stdout.includes("MATCH"));
}

// 6. Verify (mismatch)
{
  const r = run(["verify", "sha256", "abc", "0000000000000000000000000000000000000000000000000000000000000000"]);
  ok("verify sha256 abc wrong → MISMATCH exit 1", r.status === 1 && (r.stdout + r.stderr).includes("MISMATCH"));
}

// 7. Info
{
  const r = run(["info", "blake3"]);
  ok("info blake3 → shows label", r.status === 0 && r.stdout.includes("BLAKE3"));
  ok("info blake3 → shows family", r.stdout.includes("cryptographic"));
  ok("info blake3 → shows digest", r.stdout.includes("256-bit"));
}

// 8. Algorithms with filter
{
  const r = run(["algorithms", "--family", "legacy"]);
  ok("algorithms --family legacy → md5 + sha1", r.status === 0 && r.stdout.includes("md5") && r.stdout.includes("sha1"));
  ok("algorithms --family legacy → no sha256", !r.stdout.includes("sha256"));
}

// 9. Unknown algorithm → error
{
  const r = run(["hash", "fakealgo", "test"]);
  ok("unknown algorithm → non-zero exit", r.status !== 0);
}

// 10. Different encodings
{
  const r = run(["hash", "sha256", "test", "--encoding", "base64"]);
  ok("sha256 --encoding base64 → base64 string", r.status === 0 && r.stdout.trim().length === 44);
}

// 11. CRC32
{
  const r = run(["hash", "crc32", "hello"]);
  ok("hash crc32 hello → 3610a686", r.status === 0 && r.stdout.trim() === "3610a686");
}

// 12. Password hashing
{
  const r = run(["hash", "scrypt", "password123"]);
  ok("hash scrypt → 128 hex chars", r.status === 0 && /^[a-f0-9]{128}$/.test(r.stdout.trim()));
}

// Summary
console.log(`\n  ${passed} passed, ${failed} failed`);
process.exit(failed > 0 ? 1 : 0);
