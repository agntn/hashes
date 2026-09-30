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
    name: "hashes_compute",
    label: TOOL_TITLES.hashes_compute,
    description: TOOL_DESCRIPTIONS.hashes_compute,
    promptSnippet: "Use hashes_compute to hash text or produce a checksum.",
    promptGuidelines: [
      "Default output is hex; base64 and base64url are the other encodings.",
      "For scrypt and pbkdf2, keep the salt the answer names: hashes_verify needs it.",
    ],
    parameters: hashComputeSchema,
    async execute(_toolCallId, params) {
      return (await loadToolOperations()).hashCompute(params);
    },
  });

  pi.registerTool({
    name: "hashes_hmac_compute",
    label: TOOL_TITLES.hashes_hmac_compute,
    description: TOOL_DESCRIPTIONS.hashes_hmac_compute,
    promptSnippet: "Use hashes_hmac_compute for keyed hashes.",
    promptGuidelines: ["hashes_algorithms tells which algorithms have an HMAC mode."],
    parameters: hashHmacSchema,
    async execute(_toolCallId, params) {
      return (await loadToolOperations()).hashHmac(params);
    },
  });

  pi.registerTool({
    name: "hashes_verify",
    label: TOOL_TITLES.hashes_verify,
    description: TOOL_DESCRIPTIONS.hashes_verify,
    promptSnippet: "Use hashes_verify to check text against an expected digest.",
    promptGuidelines: ["Pass the encoding the expected digest is written in (default hex)."],
    parameters: hashVerifySchema,
    async execute(_toolCallId, params) {
      return (await loadToolOperations()).hashVerify(params);
    },
  });

  pi.registerTool({
    name: "hashes_algorithms",
    label: TOOL_TITLES.hashes_algorithms,
    description: TOOL_DESCRIPTIONS.hashes_algorithms,
    promptSnippet: "Use hashes_algorithms to see which hash algorithms exist and their options.",
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
