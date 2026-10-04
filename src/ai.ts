/** Vercel AI SDK tool surface over the shared hash tool definitions. */

import type { Static } from "@agntn/tools";
import { toAiTool, type AiToolOutput } from "@agntn/tools/ai";
import type { Tool } from "ai";
import type {
  AlgorithmsDetails,
  DigestDetails,
  DigestIdentity,
  DigestSearch,
  ExtendDetails,
  HashAlgorithmsParams,
  HashComputeParams,
  HashDigestExtendParams,
  HashDigestIdentifyParams,
  HashHmacParams,
  HashVerifyParams,
  VerifyDetails,
} from "./tool-operations.ts";
import type { hashDigestSearchSchema } from "../packages/shared/tool-schemas.ts";
import {
  algorithmsTool,
  computeTool,
  digestExtendTool,
  digestIdentifyTool,
  digestSearchTool,
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

/** Typed by the schema, since the SDK hands its lists over as plain arrays. */
export const hashDigestSearchTool: Tool<
  Static<typeof hashDigestSearchSchema>,
  AiToolOutput<DigestSearch>
> = toAiTool(digestSearchTool);

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
  hashes_digest_search: hashDigestSearchTool,
  hashes_algorithms: hashAlgorithmsTool,
};
