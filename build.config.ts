import { defineBuildConfig } from "obuild/config";

/**
 * typebox stays inline, so the CLI and the MCP server never resolve it from node_modules.
 * @param id - Module specifier.
 * @returns {boolean} Whether it names typebox or one of its subpaths.
 */
const isTypebox = (id: string): boolean => /^typebox(?:\/|$)/u.test(id);

/** Byte function subpaths, so plain Node loads one digest without the other 24 algorithms. */
const byteEntries = [
  "sha1",
  "md5",
  "sha2",
  "ripemd160",
  "keccak",
  "blake2b",
  "blake256",
  "crc",
  "hmac",
] as const;

/** The small digests share one chunk, since every file Node loads costs more than its bytes. */
const smallDigests = /\/src\/core\/(?:errors|hasher|sha1|md5|sha2|ripemd160|hmac|crc)\.ts$/u;

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
        ...byteEntries.map((name) => `./src/${name}.ts`),
      ],
      minifyLibs: ["typebox"],
    },
  ],
  hooks: {
    /**
     * Adds the digests chunk to the groups obuild sets for inlined libraries.
     * @param config - Rolldown output options obuild built.
     */
    rolldownOutput(config) {
      if (typeof config.codeSplitting !== "object") return;
      config.codeSplitting.groups = [
        ...(config.codeSplitting.groups ?? []),
        { name: "digests", test: smallDigests },
      ];
    },
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
