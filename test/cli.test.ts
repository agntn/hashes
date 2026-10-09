import { spawn, spawnSync } from "node:child_process";
import { argon2Sync, createHash, createHmac, hkdfSync, pbkdf2Sync, scryptSync } from "node:crypto";
import { cpSync, existsSync, mkdirSync, mkdtempSync, rmSync, symlinkSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { describe, expect, it } from "vite-plus/test";
import pkg from "../package.json" with { type: "json" };
import { hashCompute, hashVerify } from "../src/tool-operations.ts";

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

describe("hashes CLI", () => {
  it("lists every command once, in the order the tools come, without colors", () => {
    const help = run(["--help"]);
    const usage = run(["hash", "--help"]);
    const commands = help.stdout
      .split("\n")
      .filter((line) => line.startsWith("  "))
      .map((line) => line.trim().split(/\s{2,}/)[0]);

    expect(commands).toEqual([
      "hash",
      "hmac",
      "verify",
      "extend",
      "identify",
      "search",
      "algorithms, info",
      "mcp",
    ]);
    expect(usage.stdout).toContain("USAGE hashes hash [OPTIONS] <ALGORITHM> <INPUT...>");
    expect(usage.stdout).toContain(
      "previous digest (all but scrypt, pbkdf2, hkdf, evp-bytestokey, argon2id, argon2i, argon2d, bcrypt)",
    );
    expect(usage.stdout).toContain("Seed value for xxHash (xxhash)");
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

  it("hashes stdin for -, byte for byte, and writes binary digests as bytes", () => {
    const bytes = Buffer.from([0xff, 0x00, 0xfe]);
    const piped = spawnSync(process.execPath, ["src/cli.ts", "sha256", "-"], { env, input: bytes });
    const binary = spawnSync(process.execPath, ["src/cli.ts", "md5", "abc", "-e", "binary"], {
      env,
    });

    expect(run(["sha256", "-"], "piped bytes").stdout).toBe(`${sha256("piped bytes")}\n`);
    expect(piped.stdout.toString()).toBe(`${createHash("sha256").update(bytes).digest("hex")}\n`);
    expect(binary.stdout).toEqual(createHash("md5").update("abc").digest());
  });

  it("hashes the bytes --input-encoding hex spells, from the argument or stdin", () => {
    const key = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
    const hash160 = "751e76e8199196d454941c45d1b3a323f1433bd6\n";

    expect(run(["hash160", key, "--input-encoding", "hex"]).stdout).toBe(hash160);
    expect(run(["hash160", "-", "--input-encoding", "hex"], `${key}\n`).stdout).toBe(hash160);
    expect(run(["hmac", "sha256", "AA==", "k", "--input-encoding", "base64"]).stdout).toBe(
      `${createHmac("sha256", "k")
        .update(Buffer.from([0]))
        .digest("hex")}\n`,
    );
    expect(run(["verify", "sha256", "00", sha256("\0"), "--input-encoding", "hex"]).code).toBe(0);
    expect(run(["sha256", "0x00", "--input-encoding", "hex"])).toMatchObject({
      code: 1,
      stderr: "Invalid option input=4 characters: must be hex digit pairs, without a 0x prefix\n",
    });
  });

  it("reads the HMAC key as --key-encoding says", () => {
    const key = Buffer.alloc(20, 0xaa);
    const hmac = `${createHmac("sha256", key).update("m").digest("hex")}\n`;

    expect(run(["hmac", "sha256", "m", key.toString("hex"), "--key-encoding", "hex"]).stdout).toBe(
      hmac,
    );
    expect(
      run(["hmac", "sha256", "m", key.toString("base64"), "--key-encoding", "base64"]).stdout,
    ).toBe(hmac);
    expect(run(["hmac", "sha256", "m", "k", "--key-encoding", "latin1"])).toMatchObject({
      code: 1,
      stderr: "Invalid arguments at --key-encoding: must be one of utf8, hex, base64\n",
    });
  });

  it("keeps a drawn KDF salt on stderr and the digest alone on stdout", () => {
    const { stderr, stdout } = run(["pbkdf2", "pw", "--iterations", "1000"]);
    const salt = /^iterations 1000, digest sha512, keyLength 64, salt ([0-9a-f]{64})\n$/.exec(
      stderr,
    )?.[1];

    expect(salt).toBeDefined();
    expect(stdout).toBe(
      `${pbkdf2Sync("pw", Buffer.from(salt ?? "", "hex"), 1000, 64, "sha512").toString("hex")}\n`,
    );
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

  it("hashes several inputs into the lines hashes_compute gives, each quoted word kept whole", () => {
    const list = run(["sha256", "hello world", "foo", "b\u202E\nMATCH"]);
    const tool = hashCompute({
      algorithm: "sha256",
      input: ["hello world", "foo", "b\u202E\nMATCH"],
    });

    expect(list).toEqual({
      code: 0,
      stderr: "3 inputs, sha256, hex, 32 bytes\n",
      stdout: [
        `${sha256("hello world")}  "hello world"`,
        `${sha256("foo")}  "foo"`,
        `${sha256("b\u202E\nMATCH")}  "b\\u202e\\nMATCH"`,
        "",
      ].join("\n"),
    });
    expect(list.stderr + list.stdout).toBe(`${tool.content[0]?.text}\n`);
    expect(run(["sha256", "-", "x"], "piped").stdout).toBe(
      `${sha256("piped")}  "-"\n${sha256("x")}  "x"\n`,
    );
  });

  it("keeps a list going past an input it can't read, then exits 1", () => {
    const bad = run(["sha256", "00", "0x00", "--input-encoding", "hex"]);

    expect(bad).toMatchObject({ code: 1, stderr: "2 inputs, sha256, hex, 32 bytes\n" });
    expect(bad.stdout).toBe(
      `${sha256("\0")}  "00"\nERROR  "0x00"  Invalid option input=4 characters: must be hex digit pairs, without a 0x prefix\n`,
    );
    expect(run(["sha256", "-", "-"], "x")).toMatchObject({
      code: 1,
      stdout: "",
      stderr: "Invalid option input=-: stdin reads once, so only one input can be -\n",
    });
    expect(run(["md5", "a", "b", "-e", "binary"])).toMatchObject({
      code: 1,
      stdout: "",
      stderr:
        "Invalid option encoding=binary: writes one digest alone; hash several inputs in hex or base64\n",
    });
  });

  it("gives every input of a KDF list its own drawn salt on its line", () => {
    const { code, stderr, stdout } = run(["pbkdf2", "a", "b", "--iterations", "1000"]);
    const lines = stdout.trimEnd().split("\n");

    expect(code).toBe(0);
    expect(stderr).toBe(
      "2 inputs, pbkdf2, hex, 64 bytes, iterations 1000, digest sha512, keyLength 64\n",
    );
    expect(lines).toHaveLength(2);
    for (const [index, password] of ["a", "b"].entries()) {
      const [digest, label, salt] = (lines[index] ?? "").split("  ");
      expect(label).toBe(`"${password}"`);
      expect(digest).toBe(
        pbkdf2Sync(password, Buffer.from(salt?.slice(5) ?? "", "hex"), 1000, 64, "sha512").toString(
          "hex",
        ),
      );
    }
  });

  it("HMACs several inputs under the key that comes last", () => {
    const tag = (text: string): string => createHmac("sha256", "k").update(text).digest("hex");

    expect(run(["hmac", "sha256", "m", "k"]).stdout).toBe(`${tag("m")}\n`);
    expect(run(["hmac", "sha256", "a", "b c", "k"])).toEqual({
      code: 0,
      stderr: "2 inputs, HMAC-sha256, hex, 32 bytes\n",
      stdout: `${tag("a")}  "a"\n${tag("b c")}  "b c"\n`,
    });
  });

  it("verifies several candidates against the digest that comes last, exit 1 when none gives it", () => {
    const md5 = createHash("md5").update("hello").digest("hex");
    const one = run(["verify", "md5", "nope", "hello", md5]);
    const none = run(["verify", "md5", "x", "y", md5]);
    const tool = hashVerify({ algorithm: "md5", input: ["nope", "hello"], expected: md5 });

    expect(one).toMatchObject({ code: 0, stderr: "" });
    expect(one.stdout).toBe(`${tool.content[0]?.text}\n`);
    expect(one.stdout).toContain(`\nmatch     ${md5}  "hello"\n`);
    expect(none.code).toBe(1);
    expect(none.stdout).toMatch(/^MISMATCH: none of 2 inputs gives the expected md5 digest\n/);
  });

  it("identifies several hashes, a block each, exit 1 while one fits nothing", () => {
    const sha1 = createHash("sha1").update("abc").digest("hex");
    const both = run(["identify", sha1, "00".repeat(7)]);

    expect(both.code).toBe(1);
    expect(both.stderr).toBe("");
    expect(both.stdout).toMatch(
      new RegExp(
        `^"${sha1}"\\n20 bytes in hex\\. [^\\n]*\\nsha1: SHA-1, computable\\n[\\s\\S]*\\n\\n"${"00".repeat(7)}"\\n7 bytes in hex: nothing known here makes 7 bytes\\.\\n$`,
        "u",
      ),
    );
    expect(run(["identify", sha1, sha1]).code).toBe(0);
  });

  it("searches for several digests split by commas, exit 1 while one has no recipe", () => {
    const flags = ["alpha", "beta", "--joiners", '["-"]', "--cases", "as-is"];
    const both = run(["search", `${sha256("beta-alpha")},${sha256("alpha")}`, ...flags]);
    const one = run(["search", `${sha256("alpha")}, ${sha256("x")}`, ...flags]);

    expect(both).toEqual({
      code: 0,
      stderr: "Searching 44 hashes\nMATCH for 2 of 2 digests after 34 of 44 hashes\n",
      stdout: [
        `${sha256("beta-alpha")} MATCH`,
        'sha256 of the words "beta", "alpha" joined by "-", case as-is',
        'input "beta-alpha"',
        `${sha256("alpha")} MATCH`,
        'sha256 of the word "alpha", case as-is',
        'input "alpha"',
        "",
      ].join("\n"),
    });
    expect(one).toMatchObject({ code: 1 });
    expect(one.stdout).toBe(
      `${sha256("alpha")} MATCH\nsha256 of the word "alpha", case as-is\ninput "alpha"\n${sha256("x")} NO MATCH\n`,
    );
    expect(one.stderr).toMatch(
      /^Searching 44 hashes\nMATCH for 1 of 2 digests after 44 of 44 hashes\nCovered 1 to 2 of the words "alpha", "beta"; joiners "-"; cases as-is; algorithms sha256, /,
    );
  });

  it("searches for the words behind a digest, the recipe on stdout and the count on stderr", () => {
    const found = run([
      "search",
      sha256("beta-alpha"),
      "alpha",
      "beta",
      "--joiners",
      '["-"]',
      "--cases",
      "as-is",
      "--algorithms",
      "sha256",
    ]);
    const none = run([
      "search",
      sha256("x"),
      "alpha",
      "--algorithms",
      "sha256",
      "--cases",
      "lower",
    ]);
    const wrong = run(["search", sha256("x"), "alpha", "--algorithms", "sha256,md5"]);
    const missing = run(["search", sha256("x")]);
    const spaced = run(["search", sha256("a b"), "a b", "--joiners", '[" "]', "--cases", "as-is"]);

    expect(found).toEqual({
      code: 0,
      stderr: "Searching 4 hashes\nMATCH after 4 of 4 hashes\n",
      stdout: 'sha256 of the words "beta", "alpha" joined by "-", case as-is\ninput "beta-alpha"\n',
    });
    expect(none).toMatchObject({ code: 1, stdout: "" });
    expect(none.stderr).toMatch(
      /^Searching 1 hash\nNO MATCH in 1 hash\nCovered 1 of the words "alpha"/,
    );
    expect(wrong).toMatchObject({ code: 1, stdout: "" });
    expect(wrong.stderr).toContain("makes 16 bytes and the digest is 32");
    expect(missing).toMatchObject({ code: 1, stdout: "" });
    expect(missing.stderr).toBe("Invalid arguments: missing <WORDS...>\n");
    expect(spaced).toMatchObject({ code: 0 });
  });

  it("identifies a hash with the candidates on stdout and exits 1 when none fits", () => {
    const found = run(["identify", createHash("sha1").update("abc").digest("hex")]);
    const none = run(["identify", "00".repeat(7)]);

    expect(found).toEqual({
      code: 0,
      stderr: "20 bytes in hex. Candidates from the shape alone, most likely first:\n",
      stdout: [
        "sha1: SHA-1, computable",
        "ripemd160: RIPEMD-160, computable",
        "hash160: HASH160, computable",
        "sha0: SHA-0, computable",
        "Any length: scrypt, pbkdf2, hkdf, evp-bytestokey, argon2id, argon2i, argon2d, with keyLength 20",
        "",
      ].join("\n"),
    });
    expect(none).toEqual({
      code: 1,
      stderr: "7 bytes in hex: nothing known here makes 7 bytes.\n",
      stdout: "",
    });
  });

  it("refuses an expected digest that is not valid in its encoding instead of a mismatch", () => {
    const prefixed = run(["verify", "sha256", "abc", `0x${sha256("abc")}`]);
    expect(prefixed.code).toBe(1);
    expect(prefixed.stdout).toBe("");
    expect(prefixed.stderr).toContain(
      "Invalid option expected=66 characters: must be hex digit pairs, without a 0x prefix",
    );
    const base64url = run(["verify", "sha256", "abc", "+/", "-e", "base64url"]);
    expect(base64url.stdout).toBe("");
    expect(base64url.stderr).toContain("Invalid option expected=2 characters: must be base64url");
  });

  it("reports the library's errors in one line with exit code 1", () => {
    const unknown = run(["sha999", "x"]);
    expect(unknown).toMatchObject({ code: 1, stdout: "" });
    expect(unknown.stderr).toMatch(/^Unknown algorithm: sha999\. Available: sha256, [^\n]*\n$/);
    expect(run(["hmac", "blake3", "m", "k"])).toMatchObject({
      code: 1,
      stderr: "Invalid option algorithm=blake3: has no HMAC mode\n",
    });
    const family = run(["algorithms", "--family", "nope"]);
    expect(family.code).toBe(1);
    expect(family.stderr).toMatch(/^Invalid option family=nope: use one of SHA, Keccak, /);
    expect(run(["algorithms", "--category", "SHA"]).code).toBe(1);
  });

  it("refuses a flag or an argument the command does not take", () => {
    for (const [args, flag] of [
      [["sha256", "abc", "--key", "secret"], "--key"],
      [["sha256", "abc", "--rounds", "2", "--typo=3"], "--typo=3"],
      [["verify", "sha256", "abc", sha256("abc"), "--key", "x"], "--key"],
      [["hmac", "sha256", "abc", "k", "--salt", "00"], "--salt"],
      [["info", "sha256", "-x"], "-x"],
      [["search", sha256("x"), "x", "--bogus"], "--bogus"],
    ] as const) {
      const refused = run(args);
      expect(refused).toMatchObject({ code: 1, stdout: "" });
      expect(refused.stderr).toMatch(
        new RegExp(`^Invalid arguments: unknown option "${flag}"; takes `, "u"),
      );
    }
    for (const args of [
      ["extend", "sha256", "x", "y", "z", "1", "2"],
      ["info", "sha256", "md5"],
    ]) {
      expect(run(args)).toMatchObject({ code: 1, stdout: "" });
      expect(run(args).stderr).toMatch(
        /^Invalid arguments: \d+ unexpected positional arguments?\n$/,
      );
    }
    for (const command of ["hmac", "verify"]) {
      expect(run([command, "sha256", "only"])).toMatchObject({
        code: 1,
        stdout: "",
        stderr: "Invalid arguments at <INPUT...>: must not have fewer than 2 items\n",
      });
    }
    expect(run(["sha256", "--", "--key"]).stdout).toBe(`${sha256("--key")}\n`);
    expect(run(["sha256", "abc", "--inputEncoding", "utf8"]).code).toBe(1);
  });

  it("passes every advertised option as a flag and refuses one the algorithm lacks", () => {
    expect(run(["xxhash", "abc", "--seed", "1"]).stdout).toBe("bea9ca8199328908\n");
    // Reference: Python xxhash.xxh64(b"abc", seed=2**64 - 1).
    expect(run(["xxhash", "abc", "--seed", "18446744073709551615"]).stdout).toBe(
      "28306e589cc02176\n",
    );
    const scrypt = run([
      "scrypt",
      "pw",
      "--salt",
      "00112233",
      "--n",
      "1024",
      "--r",
      "1",
      "--p",
      "1",
      "--key-length",
      "16",
    ]);
    expect(scrypt.stdout).toBe(
      `${scryptSync("pw", Buffer.from("00112233", "hex"), 16, { N: 1024, r: 1, p: 1 }).toString("hex")}\n`,
    );
    const argon2 = run([
      "argon2d",
      "pw",
      "--salt",
      "0011223344556677",
      "--memory",
      "64",
      "--iterations",
      "1",
      "--parallelism",
      "1",
      "--associated-data",
      "ff",
    ]);
    expect(argon2.stdout).toBe(
      `${argon2Sync("argon2d", {
        message: "pw",
        nonce: Buffer.from("0011223344556677", "hex"),
        memory: 64,
        passes: 1,
        parallelism: 1,
        tagLength: 32,
        associatedData: Buffer.from("ff", "hex"),
      }).toString("hex")}\n`,
    );
    const twice = createHash("sha256").update(createHash("sha256").update("abc").digest("hex"));
    expect(run(["sha256", "abc", "--rounds", "2", "--chain", "hex"]).stdout).toBe(
      `${twice.digest("hex")}\n`,
    );
    expect(run(["sha256", "abc", "--salt", "deadbeef"])).toMatchObject({
      code: 1,
      stdout: "",
      stderr: "Invalid option salt=deadbeef: sha256 takes rounds, chain\n",
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

  it("derives with HKDF from hex key material and verifies without a salt", () => {
    const ikm = "0b".repeat(22);
    const okm = Buffer.from(
      hkdfSync("sha256", Buffer.from(ikm, "hex"), "", Buffer.from("f0f1", "hex"), 42),
    ).toString("hex");
    const args = ["--input-encoding", "hex", "--info", "f0f1", "--key-length", "42"];

    expect(run(["hkdf", ikm, ...args])).toMatchObject({ code: 0, stdout: `${okm}\n`, stderr: "" });
    expect(run(["verify", "hkdf", ikm, okm, ...args])).toMatchObject({ code: 0 });
  });

  it("derives OpenSSL's key and IV by its C name, with the parameters on stderr", () => {
    const keyIv =
      "2435177f1410536baad2acc155c0f94783d58384573cb0f72157443606285d3ff96efc044e0f1613bf324245c95e7411";

    expect(
      run(["EVP_BytesToKey", "password", "--salt", "0102030405060708", "--digest", "sha256"]),
    ).toMatchObject({
      code: 0,
      stdout: `${keyIv}\n`,
      stderr: "digest sha256, iterations 1, keyLength 32, ivLength 16, salt 0102030405060708\n",
    });
    expect(
      run(["evp-bytestokey", "password", "--key-length", "16", "--iv-length", "0"]),
    ).toMatchObject({ code: 0, stdout: "5f4dcc3b5aa765d61d8327deb882cf99\n", stderr: "" });
  });

  it("lists one family or category and describes one algorithm", () => {
    const names = (args: readonly string[]): string[] =>
      run(["algorithms", ...args])
        .stdout.split("\n")
        .filter((line) => / \[/u.test(line))
        .map((line) => line.split(" ")[0] ?? "");
    expect(names(["-c", "password"])).toEqual([
      "scrypt",
      "pbkdf2",
      "evp-bytestokey",
      "argon2id",
      "argon2i",
      "argon2d",
      "bcrypt",
    ]);
    expect(names(["-f", "crc"])).toEqual(["crc32", "crc64", "crc24", "crc16-xmodem"]);
    expect(names(["-f", "SHA", "-c", "legacy"])).toEqual(["sha1", "sha0"]);
    expect(run(["info", "SHA3_256"]).stdout).toMatch(/^sha3-256 \[SHA, cryptographic\] 256-bit/u);
    expect(run([]).stdout).toBe(run(["algorithms"]).stdout);
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
  const bundle = urls.includes(pathToFileURL(join(base, "dist/mcp.mjs")).href);
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
