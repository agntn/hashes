/** The hash tools, declared once for MCP, Pi, OMP and the AI SDK. Executors load on first call. */

import { defineTool, type ToolDefinition } from "@agntn/tools";
import {
  BUILTIN_FAMILIES,
  HASH_CATEGORIES,
  TOOL_DESCRIPTIONS,
  TOOL_TITLES,
} from "../packages/shared/tool-contract.ts";
import {
  hashAlgorithmsSchema,
  hashComputeSchema,
  hashDigestExtendSchema,
  hashDigestIdentifySchema,
  hashDigestSearchSchema,
  hashHmacSchema,
  hashVerifySchema,
} from "../packages/shared/tool-schemas.ts";

let operations: Promise<typeof import("./tool-operations.ts")> | undefined;

/**
 * Loads the shared executors once.
 *
 * @returns {Promise<typeof import("./tool-operations.ts")>} The executors.
 */
function loadOperations(): Promise<typeof import("./tool-operations.ts")> {
  operations ??= import("./tool-operations.ts");
  return operations;
}

/** Not idempotent: a KDF without a salt draws a new one each call. */
export const computeTool = defineTool({
  name: "hashes_compute",
  title: TOOL_TITLES.hashes_compute,
  description: TOOL_DESCRIPTIONS.hashes_compute,
  snippet: "Use hashes_compute to hash text or produce a checksum.",
  guidelines: [
    "Default output is hex; base64 and base64url are the other encodings.",
    "For scrypt, pbkdf2 and argon2, keep the salt the answer names: hashes_verify needs it.",
  ],
  effect: "read",
  idempotent: false,
  input: hashComputeSchema,
  execute: async (params) => (await loadOperations()).hashCompute(params),
});

export const hmacComputeTool = defineTool({
  name: "hashes_hmac_compute",
  title: TOOL_TITLES.hashes_hmac_compute,
  description: TOOL_DESCRIPTIONS.hashes_hmac_compute,
  snippet: "Use hashes_hmac_compute for keyed hashes.",
  guidelines: ["hashes_algorithms tells which algorithms have an HMAC mode."],
  effect: "read",
  input: hashHmacSchema,
  execute: async (params) => (await loadOperations()).hashHmac(params),
});

export const verifyTool = defineTool({
  name: "hashes_verify",
  title: TOOL_TITLES.hashes_verify,
  description: TOOL_DESCRIPTIONS.hashes_verify,
  snippet: "Use hashes_verify to check text against an expected digest.",
  guidelines: ["Pass the encoding the expected digest is written in (default hex)."],
  effect: "read",
  input: hashVerifySchema,
  execute: async (params) => (await loadOperations()).hashVerify(params),
});

export const digestExtendTool = defineTool({
  name: "hashes_digest_extend",
  title: TOOL_TITLES.hashes_digest_extend,
  description: TOOL_DESCRIPTIONS.hashes_digest_extend,
  snippet: "Use hashes_digest_extend for a length extension attack on H(secret || message).",
  guidelines: [
    "It needs the secret's length, not the secret. Unsure? Pass secretLengthMax to try a range.",
    "Send the forged message as its bytes: the padding in it is binary.",
  ],
  effect: "read",
  input: hashDigestExtendSchema,
  execute: async (params) => (await loadOperations()).hashDigestExtend(params),
});

export const digestIdentifyTool = defineTool({
  name: "hashes_digest_identify",
  title: TOOL_TITLES.hashes_digest_identify,
  description: TOOL_DESCRIPTIONS.hashes_digest_identify,
  snippet: "Use hashes_digest_identify on a hash nobody named before guessing its algorithm.",
  guidelines: [
    "The candidates come from the shape alone. Confirm one with hashes_verify on a known input.",
  ],
  effect: "read",
  input: hashDigestIdentifySchema,
  execute: async (params) => (await loadOperations()).hashDigestIdentify(params),
});

export const digestSearchTool = defineTool({
  name: "hashes_digest_search",
  title: TOOL_TITLES.hashes_digest_search,
  description: TOOL_DESCRIPTIONS.hashes_digest_search,
  snippet:
    "Use hashes_digest_search when a puzzle's password or key may be a hash of some words you have.",
  guidelines: [
    "Each word is used at most once per combination; leave out the lists you are unsure of to try every value.",
    "NO MATCH covers only the scope it names. Add words, joiners or rounds before calling the idea wrong.",
  ],
  effect: "read",
  input: hashDigestSearchSchema,
  execute: async (params) => (await loadOperations()).hashDigestSearch(params),
});

export const algorithmsTool = defineTool({
  name: "hashes_algorithms",
  title: TOOL_TITLES.hashes_algorithms,
  description: TOOL_DESCRIPTIONS.hashes_algorithms,
  snippet: "Use hashes_algorithms to see which hash algorithms exist and their options.",
  guidelines: [
    `Filter by family (${BUILTIN_FAMILIES}) or category (${HASH_CATEGORIES.join(", ")}).`,
    "Pass an algorithm name to see its options.",
  ],
  effect: "read",
  input: hashAlgorithmsSchema,
  execute: async (params) => (await loadOperations()).hashAlgorithms(params),
});

/** The hash tools, in the order every surface lists them. */
export const hashesTools: readonly ToolDefinition[] = [
  computeTool,
  hmacComputeTool,
  verifyTool,
  digestExtendTool,
  digestIdentifyTool,
  digestSearchTool,
  algorithmsTool,
];
