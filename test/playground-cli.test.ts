import { spawnSync } from "node:child_process";
import { createHash, createHmac, scryptSync } from "node:crypto";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vite-plus/test";
import { commandLine, optionFlags } from "../docs/app/utils/format.ts";

const cli = fileURLToPath(new URL("../src/cli.ts", import.meta.url));

/* Runs a playground line through sh, with `hashes` standing for the CLI in src/. */
function shell(line: string) {
  const { status, stderr, stdout } = spawnSync(
    "sh",
    ["-c", `hashes() { "$HASHES_NODE" "$HASHES_CLI" "$@"; }; ${line}`],
    { encoding: "utf8", env: { ...process.env, HASHES_CLI: cli, HASHES_NODE: process.execPath } },
  );
  return { code: status, stderr, stdout: stdout.trim() };
}

const sha256 = (text: string): string => createHash("sha256").update(text).digest("hex");

describe("the playground's CLI line", () => {
  it("keeps positionals ahead of the flags when none starts with a dash", () => {
    expect(commandLine("hashes sha256", ["hello world"], ["-e base64", ""])).toBe(
      "hashes sha256 'hello world' -e base64",
    );
  });

  it("ends the flags with -- before a positional that starts with a dash", () => {
    expect(commandLine("hashes sha256", ["-x"], ["-e base64"])).toBe(
      "hashes sha256 -e base64 -- -x",
    );
  });

  it("hashes, HMACs and verifies input that starts with a dash", () => {
    expect(shell(commandLine("hashes sha256", ["-x"]))).toMatchObject({
      code: 0,
      stdout: sha256("-x"),
    });
    expect(shell(commandLine("hashes sha256", ["-x"], ["-e base64"])).stdout).toBe(
      createHash("sha256").update("-x").digest("base64"),
    );
    expect(shell(commandLine("hashes hmac sha256", ["-x", "-k"])).stdout).toBe(
      createHmac("sha256", "-k").update("-x").digest("hex"),
    );
    expect(shell(commandLine("hashes verify sha256", ["-x", sha256("-x")]))).toMatchObject({
      code: 0,
      stdout: `MATCH sha256 ${sha256("-x")}`,
    });
  });

  it("reads a digest that starts with a dash in identify and search", () => {
    expect(shell(commandLine("hashes identify", ["-x"]))).toMatchObject({
      code: 0,
      stdout: "hex fb",
    });
    const search = shell(
      commandLine("hashes search", [sha256("-a"), "-a", "b"], ["--max-words 1"]),
    );
    expect(search.code).toBe(0);
    expect(search.stdout).toContain('input "-a"');
  });

  it("spells an algorithm's options as the kebab flags the CLI takes", () => {
    const options = { salt: "00112233", N: 1024, r: 1, p: 1, keyLength: 16 };
    const line = commandLine("hashes scrypt", ["pw"], [optionFlags(options)]);

    expect(line).toBe("hashes scrypt pw --salt 00112233 --n 1024 --r 1 --p 1 --key-length 16");
    expect(shell(line)).toMatchObject({
      code: 0,
      stdout: scryptSync("pw", Buffer.from("00112233", "hex"), 16, {
        N: 1024,
        r: 1,
        p: 1,
      }).toString("hex"),
    });
  });

  it("pipes a lone dash, which the CLI reads as stdin", () => {
    expect(shell(`printf %s - | ${commandLine("hashes sha256", ["-"])}`).stdout).toBe(sha256("-"));
  });
});
