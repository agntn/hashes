/** Vercel AI SDK tool surface over the shared hash executors. */

import { tool, type Tool } from "ai";
import { z } from "zod";
import {
  HASH_FAMILIES,
  MAX_ALGORITHM_LENGTH,
  MAX_EXPECTED_LENGTH,
  MAX_INPUT_LENGTH,
  MAX_KEY_LENGTH,
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

const algorithm = z
  .string()
  .min(1)
  .max(MAX_ALGORITHM_LENGTH)
  .describe("Algorithm name, case-insensitive");
const input = z.string().max(MAX_INPUT_LENGTH).describe("Text to hash, read as UTF-8");
const encoding = z.enum(TEXT_ENCODINGS).optional().describe("Digest encoding (default hex)");
const salt = z
  .string()
  .regex(new RegExp(SALT_PATTERN))
  .optional()
  .describe("scrypt and pbkdf2 only: salt in hex; omitted, a random one is drawn and returned");

type Output<Details> = Details & { text: string };

const hashComputeInput = z.strictObject({ algorithm, input, encoding, salt });

export const hashComputeTool: Tool<z.infer<typeof hashComputeInput>, Output<DigestDetails>> = tool({
  description: TOOL_DESCRIPTIONS.hash_compute,
  inputSchema: hashComputeInput,
  execute: (params) => {
    const { content, details } = hashCompute(params);
    return { ...details, text: content[0]?.text ?? "" };
  },
});

const hashHmacInput = z.strictObject({
  algorithm,
  input,
  key: z.string().max(MAX_KEY_LENGTH).describe("HMAC key, read as UTF-8"),
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
  expected: z.string().min(1).max(MAX_EXPECTED_LENGTH).describe("Expected digest"),
  encoding,
  salt,
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
  family: z.enum(HASH_FAMILIES).optional().describe("Family to list"),
  algorithm: algorithm.optional().describe("Algorithm to describe with its options"),
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
