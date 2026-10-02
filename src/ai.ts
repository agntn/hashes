/** Vercel AI SDK tool surface over the shared hash tool definitions. */

import { toAiTool, type AiToolOutput } from "@agntn/tools/ai";
import type { Tool } from "ai";
import type {
  AlgorithmsDetails,
  DigestDetails,
  DigestIdentity,
  ExtendDetails,
  HashAlgorithmsParams,
  HashComputeParams,
  HashDigestExtendParams,
  HashDigestIdentifyParams,
  HashHmacParams,
  HashVerifyParams,
  VerifyDetails,
} from "./tool-operations.ts";
import {
  algorithmsTool,
  computeTool,
  digestExtendTool,
  digestIdentifyTool,
  hmacComputeTool,
  verifyTool,
} from "./tools.ts";

export const hashComputeTool: Tool<HashComputeParams, AiToolOutput<DigestDetails>> = toAiTool(
  computeTool,
);

export const hashHmacTool: Tool<HashHmacParams, AiToolOutput<DigestDetails>> = toAiTool(
  hmacComputeTool,
);

export const hashVerifyTool: Tool<HashVerifyParams, AiToolOutput<VerifyDetails>> = toAiTool(
  verifyTool,
);

export const hashDigestExtendTool: Tool<
  HashDigestExtendParams,
  AiToolOutput<ExtendDetails>
> = toAiTool(digestExtendTool);

export const hashDigestIdentifyTool: Tool<
  HashDigestIdentifyParams,
  AiToolOutput<DigestIdentity>
> = toAiTool(digestIdentifyTool);

export const hashAlgorithmsTool: Tool<
  HashAlgorithmsParams,
  AiToolOutput<AlgorithmsDetails>
> = toAiTool(algorithmsTool);

/** Every hash tool, keyed by the name MCP, Pi and OMP use for it. */
export const hashTools = {
  hashes_compute: hashComputeTool,
  hashes_hmac_compute: hashHmacTool,
  hashes_verify: hashVerifyTool,
  hashes_digest_extend: hashDigestExtendTool,
  hashes_digest_identify: hashDigestIdentifyTool,
  hashes_algorithms: hashAlgorithmsTool,
};
