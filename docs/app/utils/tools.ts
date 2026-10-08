import {
  TOOL_ARGUMENTS,
  hashAlgorithms,
  hashCompute,
  hashHmac,
  hashVerify,
  type HashAlgorithmsParams,
  type HashComputeParams,
  type HashHmacParams,
  type HashVerifyParams,
  type ToolName,
} from "#tool-operations";

/** Every agent tool. Same names over MCP, Pi, OMP and the AI SDK. */
export const TOOLS = Object.keys(TOOL_ARGUMENTS) as ToolName[];

/**
 * The text `hashes_compute` hands a model, from the executor the tools run.
 *
 * @param {HashComputeParams} params - The tool arguments.
 * @returns {string} `content[0].text`.
 */
export function computeText(params: HashComputeParams): string {
  return hashCompute(params).content[0]!.text;
}

/**
 * The text `hashes_hmac_compute` hands a model.
 *
 * @param {HashHmacParams} params - The tool arguments.
 * @returns {string} `content[0].text`.
 */
export function hmacText(params: HashHmacParams): string {
  return hashHmac(params).content[0]!.text;
}

/**
 * The text `hashes_verify` hands a model, with the verdict.
 *
 * @param {HashVerifyParams} params - The tool arguments.
 * @returns {{ text: string; match: boolean; digest: string }} `content[0].text` and the details it came from.
 */
export function verifyAnswer(params: HashVerifyParams & { readonly input: string }): {
  text: string;
  match: boolean;
  digest: string;
} {
  const result = hashVerify(params);
  return { text: result.content[0]!.text, match: result.details.match, digest: result.details.digest };
}

/**
 * The text `hashes_algorithms` hands a model: the listing, one family or category, or one algorithm.
 *
 * @param {HashAlgorithmsParams} params - The tool arguments.
 * @returns {string} `content[0].text`.
 */
export function algorithmsText(params: HashAlgorithmsParams): string {
  return hashAlgorithms(params).content[0]!.text;
}
