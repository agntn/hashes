import { existsSync } from "node:fs";
import { fileURLToPath } from "node:url";

import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";

import type * as HashTools from "../../../dist/tool-operations.d.mts";
import {
  BUILTIN_FAMILIES,
  HASH_CATEGORIES,
  TOOL_DESCRIPTIONS,
  TOOL_TITLES,
} from "../../shared/tool-contract.ts";
import {
  hashAlgorithmsSchema,
  hashComputeSchema,
  hashHmacSchema,
  hashVerifySchema,
} from "../../shared/tool-schemas.ts";

const sourceModuleUrl = new URL("../../../src/tool-operations.ts", import.meta.url);
const distributionModuleUrl = new URL("../../../dist/tool-operations.mjs", import.meta.url);
let toolOperationsPromise: Promise<typeof HashTools> | undefined;

/**
 * Loads the tool executors shared with the MCP server and the OMP extension, so the tool answers
 * stay identical across surfaces: the live source in a checkout, the build in the package.
 *
 * @returns {Promise<typeof HashTools>} Shared tool operations module.
 */
function loadToolOperations(): Promise<typeof HashTools> {
  toolOperationsPromise ??= import(
    existsSync(fileURLToPath(sourceModuleUrl)) ? sourceModuleUrl.href : distributionModuleUrl.href
  ) as Promise<typeof HashTools>;

  return toolOperationsPromise;
}

export default function hashesExtension(pi: ExtensionAPI): void {
  pi.registerTool({
    name: "hash_compute",
    label: TOOL_TITLES.hash_compute,
    description: TOOL_DESCRIPTIONS.hash_compute,
    promptSnippet: "Use hash_compute to hash text or produce a checksum.",
    promptGuidelines: [
      "Default output is hex; base64 and base64url are the other encodings.",
      "For scrypt and pbkdf2, keep the salt the answer names: hash_verify needs it.",
    ],
    parameters: hashComputeSchema,
    async execute(_toolCallId, params) {
      return (await loadToolOperations()).hashCompute(params);
    },
  });

  pi.registerTool({
    name: "hash_hmac",
    label: TOOL_TITLES.hash_hmac,
    description: TOOL_DESCRIPTIONS.hash_hmac,
    promptSnippet: "Use hash_hmac for keyed hashes.",
    promptGuidelines: ["hash_algorithms tells which algorithms have an HMAC mode."],
    parameters: hashHmacSchema,
    async execute(_toolCallId, params) {
      return (await loadToolOperations()).hashHmac(params);
    },
  });

  pi.registerTool({
    name: "hash_verify",
    label: TOOL_TITLES.hash_verify,
    description: TOOL_DESCRIPTIONS.hash_verify,
    promptSnippet: "Use hash_verify to check text against an expected digest.",
    promptGuidelines: ["Pass the encoding the expected digest is written in (default hex)."],
    parameters: hashVerifySchema,
    async execute(_toolCallId, params) {
      return (await loadToolOperations()).hashVerify(params);
    },
  });

  pi.registerTool({
    name: "hash_algorithms",
    label: TOOL_TITLES.hash_algorithms,
    description: TOOL_DESCRIPTIONS.hash_algorithms,
    promptSnippet: "Use hash_algorithms to see which hash algorithms exist and their options.",
    promptGuidelines: [
      `Filter by family (${BUILTIN_FAMILIES}) or category (${HASH_CATEGORIES.join(", ")}).`,
      "Pass an algorithm name to see its options.",
    ],
    parameters: hashAlgorithmsSchema,
    async execute(_toolCallId, params) {
      return (await loadToolOperations()).hashAlgorithms(params);
    },
  });
}
