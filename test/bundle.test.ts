import { spawnSync } from "node:child_process";
import { globSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { build } from "esbuild";
import { afterAll, beforeAll, describe, expect, it } from "vite-plus/test";

const root = join(import.meta.dirname, "..");
let packed = "";

/** Packages Pi supplies to extensions, per `HOST_PROVIDED_EXTENSION_PACKAGES` in Pi 0.99. */
const hostProvidedPackages = [
  "@earendil-works/pi-agent-core",
  "@earendil-works/pi-ai",
  "@earendil-works/pi-coding-agent",
  "@earendil-works/pi-tui",
  "@mariozechner/pi-agent-core",
  "@mariozechner/pi-ai",
  "@mariozechner/pi-coding-agent",
  "@mariozechner/pi-tui",
  "@sinclair/typebox",
  "typebox",
];

/**
 * Builds the current source with `build.config.ts` into a temporary directory, never an old `dist`.
 * The child process keeps obuild's report out of the test output.
 */
beforeAll(() => {
  packed = mkdtempSync(join(tmpdir(), "hashes-bundle-"));
  const script = `
    import { build } from "obuild";
    import config from "./build.config.ts";
    const outDir = ${JSON.stringify(packed)};
    await build({
      ...config,
      cwd: ${JSON.stringify(root)},
      entries: config.entries.map((entry) => ({ ...entry, outDir, dts: false })),
    });
  `;
  const { status, stderr } = spawnSync(process.execPath, ["--input-type=module", "-e", script], {
    cwd: root,
    encoding: "utf8",
  });
  if (status !== 0) throw new Error(`obuild failed:\n${stderr}`);
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
    ["md5", 3, 4_000],
    ["sha1", 1, 3_000],
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

describe("typebox left to the host", () => {
  it("keeps the packages Pi supplies out of dependencies", () => {
    const manifest = JSON.parse(readFileSync(join(root, "package.json"), "utf8")) as {
      readonly dependencies: Readonly<Record<string, string>>;
      readonly peerDependencies: Readonly<Record<string, string>>;
    };

    expect(
      Object.keys(manifest.dependencies).filter((name) => hostProvidedPackages.includes(name)),
    ).toEqual([]);
    expect(manifest.peerDependencies["typebox"]).toBe("*");
  });

  /** A checkout's node_modules resolves a bare import anyway, so only the files prove the copy. */
  it("bundles typebox into the CLI and the MCP server", () => {
    const importers = globSync("**/*.mjs", { cwd: packed }).filter((file) =>
      /(?:from|import)\s*\(?\s*["']typebox(?:\/[^"']*)?["']/u.test(
        readFileSync(join(packed, file), "utf8"),
      ),
    );

    expect(importers).toEqual([]);
  });

  it("ships the license of the typebox it bundles", () => {
    expect(readFileSync(join(packed, "THIRD-PARTY-LICENSES.md"), "utf8")).toMatch(
      /^## typebox$[\s\S]*?Copyright \(c\) .* Haydn Paterson/mu,
    );
  });
});
