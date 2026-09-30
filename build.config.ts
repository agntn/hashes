import { defineBuildConfig } from "obuild/config";

/**
 * typebox stays inline, so the CLI and the MCP server never resolve it from node_modules.
 * @param id - Module specifier.
 * @returns {boolean} Whether it names typebox or one of its subpaths.
 */
const isTypebox = (id: string): boolean => /^typebox(?:\/|$)/u.test(id);

export default defineBuildConfig({
  entries: [
    {
      /** One bundle, so every entry shares the registry the MCP server reads. */
      type: "bundle",
      input: [
        "./src/index.ts",
        "./src/cli.ts",
        "./src/ai.ts",
        "./src/mcp.ts",
        "./src/tool-operations.ts",
      ],
      minifyLibs: ["typebox"],
    },
  ],
  hooks: {
    /**
     * obuild marks the typebox peer external by name and by subpath pattern, and both have to go.
     * @param config - Rolldown input options obuild built.
     */
    rolldownConfig(config) {
      if (!Array.isArray(config.external)) return;
      config.external = config.external.filter((entry) =>
        typeof entry === "string"
          ? !isTypebox(entry)
          : !(entry instanceof RegExp && entry.test("typebox/value")),
      );
    },
  },
});
