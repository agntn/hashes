import { execFileSync, spawnSync } from "node:child_process";
import { globSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
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
 * The root entry loads the registry's chunk, so only the module-level code esbuild can prove pure
 * drops out of it.
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
    ["sha1", 1, 3_500],
    ["sha256", 2, 4_000],
    /* SHA-256's two tables plus its own initial value, and still no registry. */
    ["Sha224Hasher", 3, 4_500],
    ["keccak256", 1, 6_000],
    ["keccakF1600", 1, 6_000],
    ["ripemd160", 5, 5_000],
    ["blake2b", 3, 8_000],
    // CRC-32 carries its bzip2 variant and the error a wrong variant throws.
    ["crc32", 0, 2_000],
    ["scrypt", 2, 8_500],
    ["argon2id", 4, 12_000],
    ["bcrypt", 0, 4_000],
  ])("%s leaves the other algorithms out", async (name, tables, limit) => {
    const code = await bundle(name);
    expect(code.match(/new (?:Int32|Uint32|Uint8)Array\(\[/g)?.length ?? 0).toBe(tables);
    // PBKDF2's digest list and the tool contract's argument descriptions.
    expect(["sha3-512", "case-insensitive"].filter((text) => code.includes(text))).toEqual([]);
    expect(code.length).toBeLessThan(limit);
  });
});

describe("one byte function subpath in plain Node", () => {
  it.each([
    ["sha1", []],
    ["md5", []],
    ["sha2", []],
    ["ripemd160", []],
    ["crc", []],
    ["adler32", []],
    ["xxhash", []],
    ["hmac", []],
    ["evp", []],
    ["scrypt", []],
    ["bcrypt", []],
    ["keccak", ["_chunks/keccak.mjs"]],
    ["blake2b", ["_chunks/blake2b.mjs"]],
    ["blake256", ["_chunks/blake256.mjs"]],
    ["argon2", ["_chunks/argon2.mjs", "_chunks/blake2b.mjs"]],
  ])("%s loads the digests chunk and nothing of the registry", (name, own) => {
    const script = `
      import { registerHooks } from "node:module";
      const loaded = [];
      registerHooks({
        load(url, context, next) {
          if (url.startsWith(${JSON.stringify(pathToFileURL(packed).href + "/")})) {
            loaded.push(url.slice(${JSON.stringify(pathToFileURL(packed).href.length + 1)}));
          }
          return next(url, context);
        },
      });
      await import(${JSON.stringify(pathToFileURL(join(packed, `${name}.mjs`)).href)});
      console.log(JSON.stringify(loaded));
    `;
    const output = execFileSync(process.execPath, ["--input-type=module", "-e", script], {
      encoding: "utf8",
    });

    expect((JSON.parse(output) as string[]).toSorted()).toEqual(
      [`${name}.mjs`, "_chunks/digests.mjs", ...own].toSorted(),
    );
  });
});

describe("typebox left to @agntn/tools", () => {
  it("keeps the packages Pi supplies out of dependencies", () => {
    const manifest = JSON.parse(readFileSync(join(root, "package.json"), "utf8")) as {
      readonly dependencies: Readonly<Record<string, string>>;
    };

    expect(
      Object.keys(manifest.dependencies).filter((name) => hostProvidedPackages.includes(name)),
    ).toEqual([]);
  });

  /** A checkout's node_modules resolves a bare import anyway, so only the files prove it. */
  it("imports typebox nowhere in the build", () => {
    const importers = globSync("**/*.mjs", { cwd: packed }).filter((file) =>
      /(?:from|import)\s*\(?\s*["']typebox(?:\/[^"']*)?["']/u.test(
        readFileSync(join(packed, file), "utf8"),
      ),
    );

    expect(importers).toEqual([]);
  });
});
