import oxfmt from "@agntn/ox/oxfmt";
import oxlint from "@agntn/ox/oxlint";
import { defineConfig } from "vite-plus";

export default defineConfig({
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
                "DigestCandidate",
                "DigestDetails",
                "DigestIdentity",
                "Hash",
                "HashInput",
                "HashOptions",
                "HashResult",
                "ToolResult",
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
  },
});
