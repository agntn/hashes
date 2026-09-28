import { spawn, spawnSync } from "node:child_process";
import { createHash, scryptSync } from "node:crypto";
import { cpSync, existsSync, mkdirSync, mkdtempSync, rmSync, symlinkSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { describe, expect, it } from "vite-plus/test";
import { normalizeMainArgs } from "../src/cli-args.ts";
import pkg from "../package.json" with { type: "json" };

const switches = new Set([
  "CI",
  "FORCE_COLOR",
  "NO_COLOR",
  "NODE_DISABLE_COLORS",
  "HASHES_DIST",
  "TEST",
]);
const env = {
  ...Object.fromEntries(Object.entries(process.env).filter(([key]) => !switches.has(key))),
  TERM: "xterm-256color",
};

function run(args: readonly string[], input?: string) {
  const { status, stderr, stdout } = spawnSync(process.execPath, ["src/cli.ts", ...args], {
    encoding: "utf8",
    env,
    ...(input === undefined ? {} : { input }),
  });
  return { code: status, stderr, stdout };
}

const sha256 = (text: string): string => createHash("sha256").update(text).digest("hex");

describe("normalizeMainArgs", () => {
  it("makes hash the default subcommand and leaves the rest alone", () => {
    expect(normalizeMainArgs([])).toEqual(["algorithms"]);
    expect(normalizeMainArgs(["sha256", "x"])).toEqual(["hash", "sha256", "x"]);
    expect(normalizeMainArgs(["verify", "md5", "x", "y"])).toEqual(["verify", "md5", "x", "y"]);
    expect(normalizeMainArgs(["mcp"])).toEqual(["mcp"]);
    expect(normalizeMainArgs(["--version"])).toEqual(["--version"]);
    expect(normalizeMainArgs(["-h"])).toEqual(["-h"]);
  });
});

describe("hashes CLI", () => {
  it("prints the usage and citty's errors without colors into a pipe", () => {
    const help = run(["--help"]);
    const usage = run(["hash", "--help"]);

    expect(help.stdout).toContain("USAGE hashes hash|hmac|verify|algorithms|info|mcp");
    expect(usage.stdout).toContain("ALGORITHM");
    for (const output of [help, usage]) {
      expect(output.stdout + output.stderr).not.toContain("\u001B");
    }
  });

  it("prints its version instead of hashing the flag", () => {
    expect(run(["--version"])).toMatchObject({ code: 0, stdout: `${pkg.version}\n` });
  });

  it("hashes text with the algorithm as the first word", () => {
    expect(run(["sha256", "abc"])).toMatchObject({
      code: 0,
      stdout: `${sha256("abc")}\n`,
      stderr: "",
    });
    expect(run(["hash", "md5", "hello", "-e", "base64"]).stdout).toBe(
      `${createHash("md5").update("hello").digest("base64")}\n`,
    );
  });

  it("hashes stdin for -", () => {
    expect(run(["sha256", "-"], "piped bytes").stdout).toBe(`${sha256("piped bytes")}\n`);
  });

  it("keeps a drawn KDF salt on stderr and the digest alone on stdout", () => {
    const { stderr, stdout } = run(["pbkdf2", "pw"]);
    expect(stdout).toMatch(/^[0-9a-f]{128}\n$/);
    expect(stderr).toMatch(/^iterations 600000, digest sha512, keyLength 64, salt [0-9a-f]{64}\n$/);
  });

  it("verifies and exits 1 on a mismatch, base64 case-sensitively", () => {
    const base64 = createHash("sha256").update("abc").digest("base64");

    expect(run(["verify", "sha256", "abc", sha256("abc").toUpperCase()])).toMatchObject({
      code: 0,
    });
    expect(run(["verify", "sha256", "abc", base64, "-e", "base64"]).stdout).toMatch(/^MATCH/);
    const lowered = run(["verify", "sha256", "abc", base64.toLowerCase(), "-e", "base64"]);
    expect(lowered.code).toBe(1);
    expect(lowered.stdout).toMatch(/^MISMATCH/);
  });

  it("reports the library's errors in one line with exit code 1", () => {
    const unknown = run(["sha999", "x"]);
    expect(unknown).toMatchObject({ code: 1, stdout: "" });
    expect(unknown.stderr).toMatch(/^Unknown algorithm: sha999\. Available: sha256, [^\n]*\n$/);
    expect(run(["hmac", "blake3", "m", "k"])).toMatchObject({
      code: 1,
      stderr: "Invalid option algorithm=blake3: has no HMAC mode\n",
    });
    expect(run(["algorithms", "--family", "nope"]).code).toBe(1);
  });

  it("passes every advertised option as a flag and refuses one the algorithm lacks", () => {
    expect(run(["xxhash", "abc", "--seed", "1"]).stdout).toBe("bea9ca8199328908\n");
    const scrypt = run([
      "scrypt",
      "pw",
      "--salt",
      "00112233",
      "--N",
      "1024",
      "--r",
      "1",
      "--p",
      "1",
      "--keyLength",
      "16",
    ]);
    expect(scrypt.stdout).toBe(
      `${scryptSync("pw", Buffer.from("00112233", "hex"), 16, { N: 1024, r: 1, p: 1 }).toString("hex")}\n`,
    );
    expect(run(["sha256", "abc", "--salt", "deadbeef"])).toMatchObject({
      code: 1,
      stdout: "",
      stderr: "Invalid option salt=deadbeef: sha256 takes no parameters\n",
    });
  });

  it("verifies a KDF digest only with its salt", () => {
    const digest = scryptSync("pw", Buffer.from("00", "hex"), 64, { N: 16384 }).toString("hex");
    expect(run(["verify", "scrypt", "pw", digest, "--salt", "00"])).toMatchObject({ code: 0 });
    expect(run(["verify", "scrypt", "pw", digest])).toMatchObject({
      code: 1,
      stderr: "Missing required option: salt (the one the expected digest was made with)\n",
    });
  });

  it("lists one family and describes one algorithm", () => {
    const listing = run(["algorithms", "-f", "password"]).stdout.trim().split("\n");
    expect(listing.slice(1).map((line) => line.split(/\s+/)[0])).toEqual(["scrypt", "pbkdf2"]);
    expect(run(["info", "SHA3_256"]).stdout).toContain("SHA3-256 (sha3-256)");
  });

  it("exits quietly when the reader closes the pipe early", async () => {
    const child = spawn(process.execPath, ["src/cli.ts", "algorithms"], { env });
    child.stdout.destroy();
    let stderr = "";
    child.stderr.setEncoding("utf8");
    child.stderr.on("data", (chunk: string) => {
      stderr += chunk;
    });
    const code = await new Promise((resolve) => child.on("close", resolve));
    expect({ code, stderr }).toEqual({ code: 0, stderr: "" });
  });
});

const root = fileURLToPath(new URL("..", import.meta.url));

/** Prints every module URL the child loaded to stderr as it exits. */
const recordLoads = `data:text/javascript,${encodeURIComponent(`
  import { registerHooks } from "node:module";
  const loaded = [];
  registerHooks({
    load(url, context, nextLoad) {
      loaded.push(url);
      return nextLoad(url, context);
    },
  });
  process.on("exit", () => process.stderr.write("\\nLOADED " + JSON.stringify(loaded) + "\\n"));
`)}`;

const initialize = `${JSON.stringify({
  jsonrpc: "2.0",
  id: 1,
  method: "initialize",
  params: {
    protocolVersion: "2025-06-18",
    capabilities: {},
    clientInfo: { name: "hashes-test", version: "1.0.0" },
  },
})}\n`;

/**
 * Runs `mcp` from a built bin, answers one initialize request and tells where the server came
 * from. stdin closes after the request, so the server exits on its own.
 * @param base - Package root the bin sits in.
 * @param extraEnv - Environment on top of the shared one.
 * @returns {{ code: number | null, from: string, name: string | undefined, stderr: string }} The
 * exit code, where the server came from, the server name from the reply and stderr.
 */
function serve(base: string, extraEnv: Readonly<Record<string, string>> = {}) {
  const { status, stderr, stdout } = spawnSync(
    process.execPath,
    ["--import", recordLoads, join(base, "dist/cli.mjs"), "mcp"],
    { encoding: "utf8", env: { ...env, ...extraEnv }, input: initialize, timeout: 20_000 },
  );
  const marker = stderr.lastIndexOf("\nLOADED ");
  const loaded: unknown = marker === -1 ? [] : JSON.parse(stderr.slice(marker + 8));
  const urls = Array.isArray(loaded) ? loaded.filter((url) => typeof url === "string") : [];
  const source = urls.includes(pathToFileURL(join(base, "src/mcp.ts")).href);
  const bundle = urls.includes(pathToFileURL(join(base, "dist/_chunks/mcp.mjs")).href);
  let from: "bundle" | "source" | "unknown" = "unknown";
  if (source && !bundle) from = "source";
  if (bundle && !source) from = "bundle";
  const name = /"serverInfo":\{"name":"([^"]+)"/.exec(stdout)?.[1];
  return { code: status, from, name, stderr };
}

/**
 * A run that answered the initialize request.
 * @param from - Where the server has to come from.
 * @returns {{ code: number, from: string, name: string }} The fields `serve` has to match.
 */
function served(from: "bundle" | "source") {
  return { code: 0, from, name: "hashes" };
}

describe.skipIf(!existsSync(join(root, "dist/cli.mjs")))("hashes mcp from the built bin", () => {
  it("serves the live source inside a checkout", () => {
    expect(serve(root)).toMatchObject(served("source"));
  });

  it("keeps the bundle under HASHES_DIST=1", () => {
    expect(serve(root, { HASHES_DIST: "1" })).toMatchObject(served("bundle"));
  });

  it("keeps the bundle when the package sits under node_modules", () => {
    // Node refuses to strip types there, so a copy that ships `src` still takes the bundle.
    const cache = join(root, "node_modules/.cache");
    mkdirSync(cache, { recursive: true });
    const nested = mkdtempSync(join(cache, "hashes-cli-"));
    try {
      for (const entry of ["dist", "src", "package.json"]) {
        cpSync(join(root, entry), join(nested, entry), { recursive: true });
      }
      expect(serve(nested)).toMatchObject(served("bundle"));
    } finally {
      rmSync(nested, { recursive: true, force: true });
    }
  });

  it("keeps the bundle in a package that ships no src", () => {
    const packaged = mkdtempSync(join(tmpdir(), "hashes-cli-"));
    try {
      for (const entry of ["dist", "packages", "package.json"]) {
        cpSync(join(root, entry), join(packaged, entry), { recursive: true });
      }
      symlinkSync(join(root, "node_modules"), join(packaged, "node_modules"), "dir");
      expect(serve(packaged)).toMatchObject(served("bundle"));
    } finally {
      rmSync(packaged, { recursive: true, force: true });
    }
  });
});
