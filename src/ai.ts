/** Vercel AI SDK tool surface over the shared hash tool definitions. */

import type { Static } from "@agntn/tools";
import { toAiTool, type AiToolOutput } from "@agntn/tools/ai";
import type { Tool } from "ai";
import type {
  AlgorithmsDetails,
  DigestBatchDetails,
  DigestDetails,
  DigestIdentity,
  DigestSearch,
  DigestSearchBatch,
  ExtendDetails,
  HashAlgorithmsParams,
  HashDigestExtendParams,
  IdentifyBatchDetails,
  VerifyBatchDetails,
  VerifyDetails,
} from "./tool-operations.ts";
import type {
  hashComputeSchema,
  hashDigestIdentifySchema,
  hashDigestSearchSchema,
  hashHmacSchema,
  hashVerifySchema,
} from "../packages/shared/tool-schemas.ts";
import {
  algorithmsTool,
  computeTool,
  digestExtendTool,
  digestIdentifyTool,
  digestSearchTool,
  hmacComputeTool,
  verifyTool,
} from "./tools.ts";

/** Typed by the schema like search, since a list of inputs comes over as a plain array. */
export const hashComputeTool: Tool<
  Static<typeof hashComputeSchema>,
  AiToolOutput<DigestDetails | DigestBatchDetails>
> = toAiTool(computeTool);

export const hashHmacTool: Tool<
  Static<typeof hashHmacSchema>,
  AiToolOutput<DigestDetails | DigestBatchDetails>
> = toAiTool(hmacComputeTool);

export const hashVerifyTool: Tool<
  Static<typeof hashVerifySchema>,
  AiToolOutput<VerifyDetails | VerifyBatchDetails>
> = toAiTool(verifyTool);

export const hashDigestExtendTool: Tool<
  HashDigestExtendParams,
  AiToolOutput<ExtendDetails>
> = toAiTool(digestExtendTool);

export const hashDigestIdentifyTool: Tool<
  Static<typeof hashDigestIdentifySchema>,
  AiToolOutput<DigestIdentity | IdentifyBatchDetails>
> = toAiTool(digestIdentifyTool);

/** Typed by the schema, since the SDK hands its lists over as plain arrays. */
export const hashDigestSearchTool: Tool<
  Static<typeof hashDigestSearchSchema>,
  AiToolOutput<DigestSearch | DigestSearchBatch>
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
