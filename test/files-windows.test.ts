import { createHash } from "node:crypto";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, describe, expect, it, vi } from "vite-plus/test";

/* Windows reads a backslash in a manifest path as a separator; join does here too. */
vi.mock("node:path", async () => {
  const path = await vi.importActual<typeof import("node:path")>("node:path");
  return {
    ...path,
    join: (...parts: readonly string[]) =>
      path.join(...parts.map((part) => part.replaceAll("\\", "/"))),
  };
});

const { checkManifest } = await import("../src/files.ts");

const base = mkdtempSync(join(tmpdir(), "hashes-windows-"));
const root = join(base, "root");
mkdirSync(root);
writeFileSync(join(base, "outside.txt"), "secret");
writeFileSync(join(root, "inside.txt"), "fine");

afterAll(() => {
  rmSync(base, { recursive: true, force: true });
});

const sha256 = (text: string): string => createHash("sha256").update(text).digest("hex");

describe("a manifest path that leaves the root through a backslash", () => {
  it("is never read, and the files after it still are", async () => {
    const check = await checkManifest(
      `SHA256 (..\\outside.txt) = ${sha256("secret")}\nSHA256 (inside.txt) = ${sha256("fine")}`,
      { root },
    );

    expect(check.results.map(({ path, status, reason }) => [path, status, reason])).toEqual([
      ["..\\outside.txt", "unreadable", "leaves the root on this system"],
      ["inside.txt", "ok", undefined],
    ]);
  });
});
