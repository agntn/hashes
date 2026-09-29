import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, readdirSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vite-plus/test";
import { builtinAlgorithms } from "../src/index.ts";

const docs = new URL("../docs/", import.meta.url);

describe("docs site", () => {
  it("has a page for every built-in algorithm, in listing order", () => {
    const pages = readdirSync(new URL("content/2.algorithms/", docs))
      .filter((file) => /^\d{2}\..+\.md$/u.test(file) && !file.startsWith("00."))
      .toSorted();
    expect(pages).toEqual(
      builtinAlgorithms.map((name, index) => `${String(index + 1).padStart(2, "0")}.${name}.md`),
    );
    for (const [index, name] of builtinAlgorithms.entries()) {
      const page = readFileSync(new URL(`content/2.algorithms/${pages[index]}`, docs), "utf8");
      expect(page).toContain(`::algorithm-facts{name="${name}"}`);
    }
  });

  it("prints the digest the landing's custom algorithm file really computes", () => {
    /* The file is a literal in the component; run it against the library and compare its comment. */
    const component = readFileSync(
      new URL("app/components/content/LandingCustom.vue", docs),
      "utf8",
    );
    const block = /const FILE = \[\n([\s\S]*?)\n\] as const;/u.exec(component)?.[1];
    expect(block).toBeDefined();
    const lines = block!
      .split("\n")
      .map((line) => line.trim().replace(/,$/u, ""))
      .map((literal): string =>
        literal.startsWith("'") ? literal.slice(1, -1) : (JSON.parse(literal) as string),
      );
    const source = lines
      .join("\n")
      .replace('"@agntn/hashes"', () =>
        JSON.stringify(new URL("../src/index.ts", import.meta.url).href),
      );
    const last = lines.at(-1)!;
    const expected = /\/\/ "([0-9a-f]+)"$/u.exec(last)?.[1];
    const call = last.replace(/;\s*\/\/.*$/u, "");
    const file = join(mkdtempSync(join(tmpdir(), "hashes-docs-")), "custom.ts");
    writeFileSync(file, `${source}\nconsole.log(${call});\n`);
    expect(execFileSync(process.execPath, [file], { encoding: "utf8" }).trim()).toBe(expected);
  });
});
