import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, readdirSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vite-plus/test";
import { builtinAlgorithms, create } from "../src/index.ts";

const docs = new URL("../docs/", import.meta.url);

const UNITS =
  "zero one two three four five six seven eight nine ten eleven twelve thirteen fourteen fifteen sixteen seventeen eighteen nineteen".split(
    " ",
  );
const TENS = "  twenty thirty forty fifty sixty seventy eighty ninety".split(" ");
const NUMBERS = new Map(
  Array.from({ length: 100 }, (_, n) => [
    n < 20
      ? UNITS[n]!
      : n % 10 === 0
        ? TENS[n / 10]!
        : `${TENS[Math.floor(n / 10)]!}-${UNITS[n % 10]!}`,
    n,
  ]),
);

/**
 * Every count written before `noun` in a file, in digits or in words.
 * @param file - Path from the repo root.
 * @param noun - Regex source for what the count counts.
 * @returns {number[]} The counts in file order.
 */
function countsBefore(file: string, noun: string): number[] {
  const text = readFileSync(new URL(`../${file}`, import.meta.url), "utf8");
  return [...text.matchAll(new RegExp(`\\b([\\w-]+) ${noun}\\b`, "giu"))]
    .map(([, count]) => (/^\d+$/u.test(count!) ? Number(count) : NUMBERS.get(count!.toLowerCase())))
    .filter((count) => count !== undefined);
}

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

describe("hand-written counts", () => {
  it.each([
    ["README.md", "(?:hash )?algorithms"],
    ["AGENTS.md", "hash and key derivation algorithms"],
  ])("counts the built-in algorithms in %s", (file, noun) => {
    const counts = countsBefore(file, noun);
    expect(counts.length).toBeGreaterThan(0);
    expect(counts).toEqual(counts.map(() => builtinAlgorithms.length));
  });

  it("counts the algorithms with HMAC", () => {
    const hmac = builtinAlgorithms.filter((name) => create(name).info().hmac).length;
    expect(countsBefore("README.md", "of them take a key")).toEqual([hmac]);
  });
});
