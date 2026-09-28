import oxfmt from "@agntn/ox/oxfmt";
import oxlint from "@agntn/ox/oxlint";
import { defineConfig } from "vite-plus";

export default defineConfig({
  fmt: {
    ...oxfmt,
    ignorePatterns: ["dist", "coverage", "CHANGELOG.md"],
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
                "DigestDetails",
                "FixedAlgorithmDefinition",
                "HashAlgorithm",
                "HashInput",
                "HashOptions",
                "HashResult",
                "NobleAlgorithmDefinition",
                "ToolResult",
              ],
            },
            { from: "lib", name: ["DataView", "Uint8Array"] },
            { from: "package", name: "TLocalizedValidationError", package: "typebox" },
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
    ignorePatterns: ["dist", "coverage"],
  },
  test: {
    include: ["test/**/*.test.ts"],
  },
  /**
   * One bundle, five inputs: the entries share their chunks and therefore any module-level state.
   * Separate bundles would each carry their own registry, so an algorithm registered through the
   * package entry would be invisible to the MCP server. Chunks keep stable names under `_chunks`,
   * as obuild wrote them.
   */
  pack: {
    entry: {
      index: "src/index.ts",
      cli: "src/cli.ts",
      ai: "src/ai.ts",
      mcp: "src/mcp.ts",
      "tool-operations": "src/tool-operations.ts",
    },
    dts: true,
    format: "esm",
    platform: "node",
    sourcemap: true,
    hash: false,
    outputOptions: {
      chunkFileNames: "_chunks/[name].mjs",
      /* JSDoc ships once, in the declarations; the runtime files keep only legal and annotation comments. */
      comments: { jsdoc: false },
    },
  },
});
