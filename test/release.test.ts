import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vite-plus/test";

const workflow = readFileSync(
  fileURLToPath(new URL("../.github/workflows/release.yml", import.meta.url)),
  "utf8",
);

/** The tag's test job, whose `hashes mcp` checks start the built bin. */
const steps = [...workflow.matchAll(/^\s*- run: (.+)$/gmu)].map((match) => match[1] ?? "");

describe("a release", () => {
  it("builds before the tests", () => {
    expect(steps).toContain("pnpm build");
    expect(steps.indexOf("pnpm build")).toBeLessThan(steps.indexOf("pnpm test"));
  });
});
