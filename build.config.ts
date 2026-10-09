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
  "adler32",
  "xxhash",
  "hmac",
  "evp",
  "scrypt",
  "argon2",
  "bcrypt",
] as const;

/** The small digests share one chunk, since every file Node loads costs more than its bytes. */
const smallDigests =
  /\/src\/core\/(?:errors|hasher|sha1|md5|sha2|ripemd160|hmac|evp|crc|adler32|xxhash|scrypt|bcrypt)\.ts$/u;

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
      /** No maps: the JS ones point at the wrong lines, the d.ts ones at a src/ we don't ship. */
      dts: { sourcemap: false },
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
