import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { chmodSync, mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vite-plus/test";
import { builtinAlgorithms, create } from "../src/index.ts";
import {
  checkManifest,
  createManifest,
  hashFile,
  manifestLine,
  parseManifest,
} from "../src/files.ts";

const sha256 = (data: string | Uint8Array): string =>
  createHash("sha256").update(data).digest("hex");

let root = "";

beforeEach(() => {
  root = mkdtempSync(join(tmpdir(), "hashes-files-"));
});

afterEach(() => {
  chmodSync(root, 0o755);
  rmSync(root, { recursive: true, force: true });
});

/**
 * Writes files under the root, making their directories.
 *
 * @param contents - Bytes or text by relative path.
 */
function files(contents: Readonly<Record<string, string | Uint8Array>>): void {
  for (const [path, data] of Object.entries(contents)) {
    mkdirSync(join(root, path, ".."), { recursive: true });
    writeFileSync(join(root, path), data);
  }
}

describe("hashFile", () => {
  it("hashes the bytes on disk, not the path, the way sha256sum does", async () => {
    files({ "fixture.txt": "hello\n" });

    const result = await hashFile(join(root, "fixture.txt"), { algorithm: "sha256" });

    expect(result.digest).toBe("5891b5b522d5df086d0ff0b110fbd9d21bb4fc7163af34d08286a2e846f6be03");
    expect(result.digest).not.toBe(sha256(join(root, "fixture.txt")));
  });

  it("gives every algorithm the digest hash() gives the same bytes, across read chunks", async () => {
    const bytes = new Uint8Array(200_000).map((_, index) => 32 + ((index * 31) % 95));
    files({ "big.bin": bytes, empty: "" });
    const costs: Readonly<Record<string, object>> = {
      scrypt: { N: 16, salt: "00" },
      pbkdf2: { iterations: 1, salt: "00" },
      argon2id: { memory: 8, iterations: 1, parallelism: 1, salt: "0000000000000000" },
      argon2i: { memory: 8, iterations: 1, parallelism: 1, salt: "0000000000000000" },
      argon2d: { memory: 8, iterations: 1, parallelism: 1, salt: "0000000000000000" },
      bcrypt: { cost: 4, salt: "00000000000000000000000000000000" },
      "evp-bytestokey": { salt: "0000000000000000" },
    };

    files({ "short.bin": bytes.subarray(0, 50) });
    for (const algorithm of builtinAlgorithms) {
      const options = Object.hasOwn(costs, algorithm) ? costs[algorithm]! : {};
      const big = algorithm === "bcrypt" ? "short.bin" : "big.bin";
      for (const name of [big, "empty"]) {
        const data =
          name === "empty"
            ? new Uint8Array()
            : name === "short.bin"
              ? bytes.subarray(0, 50)
              : bytes;
        const expected = create(algorithm).hash(data, options);
        const actual = await hashFile(join(root, name), { algorithm, ...options });
        expect([algorithm, name, actual]).toEqual([algorithm, name, expected]);
      }
    }
  });

  it("matches node:crypto on a file bigger than one read", async () => {
    const bytes = new Uint8Array(300_000).map((_, index) => index & 0xff);
    files({ "big.bin": bytes });

    for (const [ours, node] of [
      ["sha256", "sha256"],
      ["sha512", "sha512"],
      ["md5", "md5"],
      ["sha3-256", "sha3-256"],
      ["blake2b", "blake2b512"],
    ] as const) {
      const { digest } = await hashFile(join(root, "big.bin"), { algorithm: ours });
      expect(digest).toBe(createHash(node).update(bytes).digest("hex"));
    }
  });

  it("keeps the options, such as rounds and the encoding", async () => {
    files({ abc: "abc" });
    const twice = sha256(createHash("sha256").update("abc").digest());

    const rounds = await hashFile(join(root, "abc"), { algorithm: "sha256", rounds: 2 });
    const base64 = await hashFile(join(root, "abc"), { algorithm: "sha256", encoding: "base64" });

    expect(rounds).toMatchObject({ digest: twice, options: { rounds: 2, chain: "bytes" } });
    expect(base64.digest).toBe(createHash("sha256").update("abc").digest("base64"));
  });

  it("names a file it can't read", async () => {
    await expect(hashFile(join(root, "nope"), { algorithm: "sha256" })).rejects.toThrow(
      `Can't read ${JSON.stringify(join(root, "nope"))}: ENOENT`,
    );
  });
});

describe("manifests", () => {
  it("lists every regular file sorted by path, in lines sha256sum -c reads", async () => {
    files({
      "b.bin": new Uint8Array([0, 255, 10, 13]),
      "a b.txt": "hello\n",
      "dir/new\nline": "x",
      "cr\rx": "y",
      "back\\slash": "z",
      empty: "",
    });

    const manifest = await createManifest({ algorithm: "sha256", root });

    expect(manifest.entries.map((entry) => entry.path)).toEqual([
      "a b.txt",
      "b.bin",
      "back\\slash",
      "cr\rx",
      "dir/new\nline",
      "empty",
    ]);
    expect(manifest.text).toBe(
      [
        `SHA256 (a b.txt) = ${sha256("hello\n")}`,
        `SHA256 (b.bin) = ${sha256(new Uint8Array([0, 255, 10, 13]))}`,
        `\\SHA256 (back\\\\slash) = ${sha256("z")}`,
        `\\SHA256 (cr\\rx) = ${sha256("y")}`,
        `\\SHA256 (dir/new\\nline) = ${sha256("x")}`,
        `SHA256 (empty) = ${sha256("")}`,
        "",
      ].join("\n"),
    );
    writeFileSync(join(root, "SUMS"), manifest.text);
    const gnu = spawnSync("sha256sum", ["--check", "--status", "SUMS"], { cwd: root });
    expect(gnu.status).toBe(0);
  });

  it("keeps a leading BOM and Unicode line breaks in a name, as sha256sum does", async () => {
    files({ "\uFEFFa": "bom", a: "plain", "b\u2028c": "ls", "d\u2029": "ps", "e\u0085f": "nel" });

    const manifest = await createManifest({ algorithm: "sha256", root });
    writeFileSync(join(root, "SUMS"), manifest.text);
    const gnu = spawnSync("sha256sum", ["--check", "--status", "SUMS"], { cwd: root });

    expect(manifest.entries.map((entry) => entry.path).toSorted()).toEqual(
      ["\uFEFFa", "a", "b\u2028c", "d\u2029", "e\u0085f"].toSorted(),
    );
    expect(manifest.entries.find((entry) => entry.path === "\uFEFFa")?.digest).toBe(sha256("bom"));
    expect(gnu.status).toBe(0);
    expect(
      await checkManifest(manifest.text, { root, strict: true, manifest: join(root, "SUMS") }),
    ).toMatchObject({ ok: true });
  });

  it("reads back what it writes, and what sha256sum writes", async () => {
    files({ "a b": "1", "c\nd": "2", "e\\f": "3" });
    const ours = await createManifest({ algorithm: "md5", root });
    const tagged = spawnSync("sha256sum", ["--tag", "a b", "c\nd", "e\\f"], {
      cwd: root,
      encoding: "utf8",
    }).stdout;
    const plain = spawnSync("sha256sum", ["a b", "c\nd", "e\\f"], {
      cwd: root,
      encoding: "utf8",
    }).stdout;

    expect(parseManifest(ours.text).map(({ line: _line, ...entry }) => entry)).toEqual(
      ours.entries,
    );
    expect(parseManifest(tagged).map((entry) => entry.path)).toEqual(["a b", "c\nd", "e\\f"]);
    expect(parseManifest(plain, "sha256")).toEqual(parseManifest(tagged));
    expect(() => parseManifest(plain)).toThrow(
      "Manifest line 1 names no algorithm; pass the one that made the manifest",
    );
  });

  it("writes the tag coreutils uses, or the registry name where it has none", () => {
    expect(manifestLine({ algorithm: "blake2b-256", path: "x", digest: "00" })).toBe(
      "BLAKE2b-256 (x) = 00",
    );
    expect(manifestLine({ algorithm: "blake3", path: "x", digest: "00" })).toBe("blake3 (x) = 00");
  });

  it("checks a good manifest, then names each mismatched, missing and extra file", async () => {
    files({ keep: "same", change: "before", gone: "soon", "dir/inner": "i" });
    const { text } = await createManifest({ algorithm: "sha256", root });

    expect(await checkManifest(text, { root })).toMatchObject({ ok: true });

    files({ change: "after", added: "new" });
    rmSync(join(root, "gone"));
    const loose = await checkManifest(text, { root });
    const strict = await checkManifest(text, { root, strict: true });

    expect(loose.ok).toBe(false);
    expect(loose.results.map(({ path, status }) => [path, status])).toEqual([
      ["change", "mismatch"],
      ["dir/inner", "ok"],
      ["gone", "missing"],
      ["keep", "ok"],
    ]);
    expect(loose.results[0]).toMatchObject({ expected: sha256("before"), actual: sha256("after") });
    expect(strict.results.at(-1)).toEqual({ path: "added", status: "extra" });
    expect(
      (await checkManifest(text, { root, strict: true, exclude: ["added"] })).results,
    ).toHaveLength(4);
  });

  it("reports a file it can't read instead of stopping", async () => {
    files({ locked: "x", open: "y" });
    const { text } = await createManifest({ algorithm: "sha256", root });
    chmodSync(join(root, "locked"), 0);
    const readable = spawnSync("cat", [join(root, "locked")]).status === 0;

    const { results } = await checkManifest(text, { root });

    if (readable) return; // root can read anything, so there's nothing to report
    expect(results).toEqual([
      {
        path: "locked",
        algorithm: "sha256",
        expected: sha256("x"),
        status: "unreadable",
        reason: "EACCES",
      },
      {
        path: "open",
        algorithm: "sha256",
        expected: sha256("y"),
        status: "ok",
        actual: sha256("y"),
      },
    ]);
  });

  it("reports a file the algorithm refuses and checks the rest", async () => {
    files({ a: "text", b: "more" });
    const { text } = await createManifest({ algorithm: "ntlm", root });
    files({ a: new Uint8Array([0xff]) });

    const { results } = await checkManifest(text, { root });

    expect(results.map(({ path, status, reason }) => [path, status, reason])).toEqual([
      ["a", "unreadable", "ntlm hashes text, and the input is not valid UTF-8"],
      ["b", "ok", undefined],
    ]);
  });

  it("never follows a symlink, to a file or through a directory", async () => {
    const outside = mkdtempSync(join(tmpdir(), "hashes-outside-"));
    try {
      writeFileSync(join(outside, "secret"), "s");
      files({ real: "r" });
      symlinkSync(join(outside, "secret"), join(root, "link"));
      symlinkSync(outside, join(root, "out"));

      const manifest = await createManifest({ algorithm: "sha256", root });
      const check = await checkManifest(
        [
          `SHA256 (link) = ${sha256("s")}`,
          `SHA256 (out/secret) = ${sha256("s")}`,
          `SHA256 (real) = ${sha256("r")}`,
        ].join("\n"),
        { root },
      );

      expect(manifest.entries.map((entry) => entry.path)).toEqual(["real"]);
      expect(manifest.skipped).toEqual(["link", "out"]);
      expect(check.results.map(({ status, reason }) => [status, reason])).toEqual([
        ["unreadable", "is a symlink, which a check never follows"],
        ["unreadable", "sits behind a symlinked directory"],
        ["ok", undefined],
      ]);
    } finally {
      rmSync(outside, { recursive: true, force: true });
    }
  });

  it("refuses a path that leaves the root, whatever the line claims", () => {
    for (const path of ["../up", "/etc/passwd", "a/../../b", "a//b", "C:\\x", ""]) {
      expect(() => parseManifest(`SHA256 (${path}) = ${sha256("")}`)).toThrow(/^Manifest line 1/u);
    }
    expect(parseManifest(`SHA256 (./a/./b) = ${sha256("")}`)[0]?.path).toBe("a/b");
  });

  it("leaves the manifest out of its own inventory, and the excluded directories whole", async () => {
    files({ "a.txt": "a", "node_modules/x/y.js": "y", "logs/run.log": "l", "logs/keep.txt": "k" });
    const output = join(root, "SUMS");
    writeFileSync(output, "old");

    const manifest = await createManifest({
      algorithm: "sha256",
      root,
      output,
      exclude: ["node_modules/**", "**/*.log"],
    });
    writeFileSync(output, manifest.text);

    expect(manifest.entries.map((entry) => entry.path)).toEqual(["a.txt", "logs/keep.txt"]);
    expect(
      (
        await checkManifest(manifest.text, {
          root,
          strict: true,
          manifest: output,
          exclude: ["node_modules/**", "**/*.log"],
        })
      ).ok,
    ).toBe(true);
  });

  it("refuses an empty selection and an empty manifest: neither proves a thing", async () => {
    files({ "only.log": "x" });

    await expect(createManifest({ algorithm: "sha256", root, exclude: ["*.log"] })).rejects.toThrow(
      "holds no files to list, and an empty manifest proves nothing",
    );
    expect(() => parseManifest("\n\n")).toThrow(
      "The manifest lists no files, and an empty manifest proves nothing",
    );
  });

  it("refuses what a manifest can't carry: a KDF, a short digest, an unknown escape", () => {
    expect(() => parseManifest(`pbkdf2 (x) = ${sha256("")}`)).toThrow(
      "derives keys from a salt and a cost, which a checksum manifest has no place for",
    );
    expect(() => parseManifest("SHA256 (x) = abcd")).toThrow(
      "Manifest line 1 has 4 hex digits, and sha256 gives 64",
    );
    expect(() => parseManifest(`\\SHA256 (a\\tb) = ${sha256("")}`)).toThrow(
      "Manifest line 1 has an unknown escape \\t in its path",
    );
    expect(() => parseManifest("not a line")).toThrow("Manifest line 1 is neither");
  });

  it("refuses a file name that isn't UTF-8, since no line could name it", async () => {
    const name = Buffer.from([0x66, 0xff]);
    writeFileSync(Buffer.concat([Buffer.from(`${root}/`), name]), "x");

    await expect(createManifest({ algorithm: "sha256", root })).rejects.toThrow(
      "A file name in the root is not UTF-8 (66ff), so no manifest can name it",
    );
  });
});
