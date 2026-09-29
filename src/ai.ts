/** Vercel AI SDK tool surface over the shared hash executors. */

import { tool, type Tool } from "ai";
import { z } from "zod";
import {
  HASH_CATEGORIES,
  INPUT_ENCODINGS,
  MAX_ALGORITHM_LENGTH,
  MAX_EXPECTED_LENGTH,
  MAX_FAMILY_LENGTH,
  MAX_INPUT_LENGTH,
  MAX_KEY_LENGTH,
  MAX_PARAMETER_LENGTH,
  MAX_PARAMETERS,
  PARAMETER_NAME_PATTERN,
  PARAMETER_DESCRIPTIONS as d,
  SALT_PATTERN,
  TEXT_ENCODINGS,
  TOOL_DESCRIPTIONS,
  hashAlgorithms,
  hashCompute,
  hashHmac,
  hashVerify,
  type AlgorithmsDetails,
  type DigestDetails,
  type VerifyDetails,
} from "./tool-operations.ts";

const algorithm = z.string().min(1).max(MAX_ALGORITHM_LENGTH).describe(d.algorithm);
const input = z.string().max(MAX_INPUT_LENGTH).describe(d.input);
const inputEncoding = z.enum(INPUT_ENCODINGS).optional().describe(d.inputEncoding);
const encoding = z.enum(TEXT_ENCODINGS).optional().describe(d.encoding);
const salt = z.string().regex(new RegExp(SALT_PATTERN)).optional();
const parameters = z
  .record(
    z.string().regex(new RegExp(PARAMETER_NAME_PATTERN)),
    z.union([z.number().int(), z.string().max(MAX_PARAMETER_LENGTH)]),
  )
  .refine(
    (value) => Object.keys(value).length <= MAX_PARAMETERS,
    `at most ${MAX_PARAMETERS} entries`,
  )
  .optional()
  .describe(d.parameters);

type Output<Details> = Details & { text: string };

const hashComputeInput = z.strictObject({
  algorithm,
  input,
  inputEncoding,
  encoding,
  salt: salt.describe(d.salt),
  parameters,
});

export const hashComputeTool: Tool<z.infer<typeof hashComputeInput>, Output<DigestDetails>> = tool({
  description: TOOL_DESCRIPTIONS.hash_compute,
  inputSchema: hashComputeInput,
  execute: (params) => {
    const { content, details } = hashCompute(params);
    return { ...details, text: content[0]?.text ?? "" };
  },
});

const hashHmacInput = z.strictObject({
  algorithm: algorithm.describe(d.hmacAlgorithm),
  input,
  inputEncoding,
  key: z.string().max(MAX_KEY_LENGTH).describe(d.key),
  keyEncoding: z.enum(INPUT_ENCODINGS).optional().describe(d.keyEncoding),
  encoding,
});

export const hashHmacTool: Tool<z.infer<typeof hashHmacInput>, Output<DigestDetails>> = tool({
  description: TOOL_DESCRIPTIONS.hash_hmac,
  inputSchema: hashHmacInput,
  execute: (params) => {
    const { content, details } = hashHmac(params);
    return { ...details, text: content[0]?.text ?? "" };
  },
});

const hashVerifyInput = z.strictObject({
  algorithm,
  input,
  inputEncoding,
  expected: z.string().min(1).max(MAX_EXPECTED_LENGTH).describe(d.expected),
  encoding: z.enum(TEXT_ENCODINGS).optional().describe(d.expectedEncoding),
  salt: salt.describe(d.verifySalt),
  parameters,
});

export const hashVerifyTool: Tool<z.infer<typeof hashVerifyInput>, Output<VerifyDetails>> = tool({
  description: TOOL_DESCRIPTIONS.hash_verify,
  inputSchema: hashVerifyInput,
  execute: (params) => {
    const { content, details } = hashVerify(params);
    return { ...details, text: content[0]?.text ?? "" };
  },
});

const hashAlgorithmsInput = z.strictObject({
  category: z.enum(HASH_CATEGORIES).optional().describe(d.category),
  family: z.string().min(1).max(MAX_FAMILY_LENGTH).optional().describe(d.family),
  algorithm: algorithm.optional().describe(d.describe),
});

export const hashAlgorithmsTool: Tool<
  z.infer<typeof hashAlgorithmsInput>,
  Output<AlgorithmsDetails>
> = tool({
  description: TOOL_DESCRIPTIONS.hash_algorithms,
  inputSchema: hashAlgorithmsInput,
  execute: (params) => {
    const { content, details } = hashAlgorithms(params);
    return { ...details, text: content[0]?.text ?? "" };
  },
});

/** Every hash tool, keyed by the name MCP, Pi and OMP use for it. */
export const hashTools = {
  hash_compute: hashComputeTool,
  hash_hmac: hashHmacTool,
  hash_verify: hashVerifyTool,
  hash_algorithms: hashAlgorithmsTool,
};
