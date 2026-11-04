/** Vercel AI SDK tool surface over the shared hash tool definitions. */

import { toAiTools, type AiTools } from "@agntn/tools/ai";
import { hashesTools } from "./tools.ts";

/** Every hash tool, keyed by the name MCP, Pi and OMP use for it, so a new tool can't miss it. */
export const hashTools: AiTools<typeof hashesTools> = toAiTools(hashesTools);

export const hashComputeTool = hashTools.hashes_compute;
export const hashHmacTool = hashTools.hashes_hmac_compute;
export const hashVerifyTool = hashTools.hashes_verify;
export const hashDigestExtendTool = hashTools.hashes_digest_extend;
export const hashDigestIdentifyTool = hashTools.hashes_digest_identify;
export const hashDigestSearchTool = hashTools.hashes_digest_search;
export const hashAlgorithmsTool = hashTools.hashes_algorithms;
