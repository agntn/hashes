import { defineBuildConfig } from "obuild/config";

/** Byte function subpaths, so plain Node loads one digest without the registry. */
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
  "evp",
  "scrypt",
  "argon2",
] as const;

/** The small digests share one chunk, since every file Node loads costs more than its bytes. */
const smallDigests =
  /\/src\/core\/(?:errors|hasher|sha1|md5|sha2|ripemd160|hmac|evp|crc|scrypt)\.ts$/u;

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
        "./src/tools.ts",
        ...byteEntries.map((name) => `./src/${name}.ts`),
      ],
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
  },
});
