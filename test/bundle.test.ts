import { spawnSync } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { build } from "esbuild";
import { afterAll, beforeAll, describe, expect, it } from "vite-plus/test";

const root = join(import.meta.dirname, "..");
let packed = "";

/**
 * Packs the current source with the project's own `vp pack` config, so the test never measures a
 * `dist` left over from an older checkout. Declarations are skipped; the runtime files come out
 * byte for byte as `pnpm build` writes them.
 */
beforeAll(() => {
  packed = mkdtempSync(join(tmpdir(), "hashes-bundle-"));
  const bin = fileURLToPath(import.meta.resolve("vite-plus/bin"));
  const { status, stderr } = spawnSync(
    process.execPath,
    [bin, "pack", "--out-dir", packed, "--no-dts"],
    { cwd: root, encoding: "utf8" },
  );
  if (status !== 0) throw new Error(`vp pack failed:\n${stderr}`);
});

afterAll(() => {
  if (packed) rmSync(packed, { recursive: true, force: true });
});

/**
 * Bundles a consumer of one export from the packed package the way Wrangler does, with esbuild.
 * All of `src` is one chunk in the output, so only the module-level code esbuild can prove pure drops
 * out of it.
 *
 * @param name - The export to import.
 * @returns {Promise<string>} The minified bundle.
 */
async function bundle(name: string): Promise<string> {
  const entry = join(packed, "index.mjs");
  const { outputFiles } = await build({
    stdin: {
      contents: `import { ${name} } from ${JSON.stringify(entry)}; console.log(${name});`,
      resolveDir: root,
    },
    bundle: true,
    minify: true,
    format: "esm",
    platform: "browser",
    write: false,
    logLevel: "silent",
  });
  return outputFiles[0]!.text;
}

describe("one byte function bundled with esbuild", () => {
  // Every one of these came out near 20 kB with all 18 constant tables before the fix. The count
  // catches one table coming back, which is too small to show in the size.
  it.each([
    ["sha256", 2, 4_000],
    ["keccak256", 1, 6_000],
    ["ripemd160", 5, 5_000],
    ["blake2b", 3, 8_000],
    ["crc32", 0, 1_500],
  ])("%s leaves the other algorithms out", async (name, tables, limit) => {
    const code = await bundle(name);
    expect(code.match(/new (?:Int32|Uint32|Uint8)Array\(\[/g)?.length ?? 0).toBe(tables);
    // PBKDF2's digest list and the tool contract's argument descriptions.
    expect(["sha3-512", "case-insensitive"].filter((text) => code.includes(text))).toEqual([]);
    expect(code.length).toBeLessThan(limit);
  });
});
