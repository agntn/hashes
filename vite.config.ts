import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import oxfmt from "@agntn/ox/oxfmt";
import oxlint from "@agntn/ox/oxlint";
import { defineConfig } from "vite-plus";

const { compilerOptions } = JSON.parse(
  readFileSync(new URL("tsconfig.json", import.meta.url), "utf8"),
) as { compilerOptions: { target?: string; verbatimModuleSyntax?: boolean } };

/** Root tsconfig for every transform: docs/tsconfig.json only points at a `.nuxt/` CI never has. */
const transformOverride: object = {
  tsconfig: {
    compilerOptions: {
      target: compilerOptions.target,
      verbatimModuleSyntax: compilerOptions.verbatimModuleSyntax,
    },
  },
};

export default defineConfig({
  oxc: { ...transformOverride },
  fmt: {
    ...oxfmt,
    ignorePatterns: ["dist", "coverage", "docs", "CHANGELOG.md"],
  },
  lint: {
    ...oxlint,
    rules: {
      ...oxlint.rules,
      "typescript/prefer-readonly-parameter-types": [
        "error",
        {
          allow: [
            /* Algorithms, results and inputs carry bytes and methods; hashing never writes to them. */
            {
              from: "file",
              name: [
                "AlgorithmInfo",
                "BatchError",
                "DigestCandidate",
                "DigestDetails",
                "DigestIdentity",
                "Hash",
                "HashInput",
                "HashOptions",
                "HashResult",
                "ToolResult",
                "VerifyDetails",
              ],
            },
            { from: "lib", name: ["DataView", "Int32Array", "Uint32Array", "Uint8Array"] },
            {
              from: "package",
              name: ["ExtensionAPI", "ToolDefinition"],
              package: "@earendil-works/pi-coding-agent",
            },
            {
              from: "package",
              name: ["AgentToolResult", "ExtensionAPI", "Theme", "ToolDefinition"],
              package: "@oh-my-pi/pi-coding-agent",
            },
          ],
          ignoreInferredTypes: true,
        },
      ],
    },
    ignorePatterns: ["dist", "coverage", "docs"],
  },
  test: {
    include: ["test/**/*.test.ts"],
    alias: { "@agntn/hashes/mcp": fileURLToPath(new URL("src/mcp.ts", import.meta.url)) },
  },
});
