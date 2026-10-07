import { serverInfo } from "../../../src/server-info.ts";

/** Introduces itself like `hashes mcp`, with the Docus page tools beside the hash ones. */
export default defineMcpHandler({ ...serverInfo });
