import { existsSync } from "node:fs";
import { join } from "node:path";
import { build } from "esbuild";
import { describe, expect, it } from "vite-plus/test";

const root = join(import.meta.dirname, "..");
const entry = join(root, "dist/index.mjs");

/**
 * Bundles a consumer of one export from the built package the way Wrangler does, with esbuild.
 * All of `src` is one chunk in `dist`, so only the module-level code esbuild can prove pure drops
 * out of it.
 *
 * @param name - The export to import.
 * @returns {Promise<string>} The minified bundle.
 */
async function bundle(name: string): Promise<string> {
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

describe.skipIf(!existsSync(entry))("one byte function bundled with esbuild", () => {
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
