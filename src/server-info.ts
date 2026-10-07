import type { McpServerInfo } from "@agntn/tools/mcp";
import { version } from "./version.ts";

/** How both MCP servers introduce themselves, so a connector card isn't just a name. */
export const serverInfo = {
  name: "hashes",
  version,
  description:
    "Hash, HMAC and verify with SHA-256, BLAKE3, Keccak-256, Argon2 and the rest of the gang. Nothing you send gets kept.",
  icons: [
    { src: "https://hashes.agntn.dev/favicon.svg", mimeType: "image/svg+xml", sizes: ["any"] },
    { src: "https://hashes.agntn.dev/icon-512.png", mimeType: "image/png", sizes: ["512x512"] },
  ],
} satisfies McpServerInfo;
