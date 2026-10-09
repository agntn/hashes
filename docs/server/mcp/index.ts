import { toToolkitTools } from "@agntn/tools/toolkit";
import { defineMcpHandler, getMcpTools } from "@nuxtjs/mcp-toolkit/server";
import { memoryCappedTools } from "../../../src/mcp.ts";
import { serverInfo } from "../../../src/server-info.ts";

/** Most bytes a KDF may fill here, half the 128 MB a Workers isolate gets. */
const WORKER_MEMORY = 64 * 1024 * 1024;

const hashTools = toToolkitTools(serverInfo, memoryCappedTools(WORKER_MEMORY));

/** Introduces itself like `hashes mcp`, and serves its tools after the Docus page tools. */
export default defineMcpHandler({
  ...serverInfo,
  tools: async (event) => [...(await getMcpTools({ event })), ...hashTools],
});
