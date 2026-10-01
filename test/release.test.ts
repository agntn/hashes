import { readFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vite-plus/test";

const root = fileURLToPath(new URL("..", import.meta.url));

const read = (path: string) => readFileSync(join(root, path), "utf8");

const manifest = JSON.parse(read("package.json")) as { scripts: Record<string, string> };

/** Each way a release runs the tests, whose `hashes mcp` checks start the built bin. */
const releaseSteps: Record<string, readonly string[]> = {
  "the Publish workflow": [
    ...read(".github/workflows/publish.yml").matchAll(/^\s*- run: (.+)$/gmu),
  ].map((match) => match[1] ?? ""),
  "pnpm release": manifest.scripts.release?.split(" && ") ?? [],
};

describe("a release", () => {
  it.each(Object.entries(releaseSteps))("builds before the tests in %s", (_, steps) => {
    expect(steps).toContain("pnpm build");
    expect(steps.indexOf("pnpm build")).toBeLessThan(steps.indexOf("pnpm test"));
  });
});
