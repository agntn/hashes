import { existsSync } from "node:fs";
import { fileURLToPath } from "node:url";

import type { ExtensionAPI } from "@oh-my-pi/pi-coding-agent";
import { Text } from "@oh-my-pi/pi-coding-agent";
import { sanitizeLine } from "@agntn/tools";
import { registerOmpTools, type OmpRenderers, type OmpResultView } from "@agntn/tools/omp";

import type * as HashTools from "../../../dist/tools.d.mts";

const sourceModulePath = fileURLToPath(new URL("../../../src/tools.ts", import.meta.url));

/**
 * Both specifiers stay literal: compiled OMP resolves bare imports only where it sees them.
 *
 * @returns {Promise<typeof HashTools>} The tool definitions.
 */
function loadTools(): Promise<typeof HashTools> {
  return (
    existsSync(sourceModulePath)
      ? import("../../../src/tools.ts")
      : import("../../../dist/tools.mjs")
  ) as Promise<typeof HashTools>;
}

/** Longest input preview a status line shows. */
const PREVIEW_LENGTH = 40;

/**
 * Shortens a value for a status line after sanitizing it.
 *
 * @param value - Any argument value.
 * @returns {string} The clean value, cut to `PREVIEW_LENGTH` characters.
 */
export function preview(value: unknown): string {
  const clean = sanitizeLine(value);
  return clean.length > PREVIEW_LENGTH ? `${clean.slice(0, PREVIEW_LENGTH - 1)}…` : clean;
}

/**
 * Names the algorithm and previews the input. The HMAC key stays off the terminal.
 *
 * @param args - Call arguments.
 * @returns {string} The call summary.
 */
function describeDigestCall(args: Readonly<Record<string, unknown>>): string {
  const input = args["input"];
  const what = Array.isArray(input) ? `${input.length} inputs` : preview(input);
  return `${sanitizeLine(args["algorithm"])} ${what}`;
}

/**
 * Reads the entries of a list result.
 *
 * @param result - Tool result from the host.
 * @returns {unknown[] | undefined} The entries, or nothing for a single answer.
 */
function listItems(result: OmpResultView): unknown[] | undefined {
  const items = (result.details as { items?: unknown } | undefined)?.items;
  return Array.isArray(items) ? items : undefined;
}

/**
 * Summarizes a digest result: the algorithm and the digest, or how many digests a list got.
 *
 * @param result - Tool result from the host.
 * @returns {string[]} The summary, or nothing without a digest.
 */
function describeDigest(result: OmpResultView): string[] {
  const items = listItems(result);
  if (items !== undefined) return [`${items.length} digests`];
  const { details } = result;
  if (typeof details !== "object" || details === null || !("digest" in details)) return [];
  const { algorithm, digest } = details as { algorithm?: unknown; digest?: unknown };
  return [`${sanitizeLine(algorithm)} ${preview(digest)}`];
}

/**
 * Summarizes a verdict: match or mismatch.
 *
 * @param result - Tool result from the host.
 * @returns {string[]} The verdict, or nothing without one.
 */
function describeVerdict(result: OmpResultView): string[] {
  const items = listItems(result);
  if (items !== undefined) {
    const matches = (result.details as { matches?: unknown }).matches;
    return [`${typeof matches === "number" ? matches : 0} of ${items.length} match`];
  }
  const { details } = result;
  if (typeof details !== "object" || details === null || !("match" in details)) return [];
  return [details.match ? "match" : "mismatch"];
}

/**
 * Counts the algorithms a listing returned.
 *
 * @param result - Tool result from the host.
 * @returns {string[]} The count, or nothing without a listing.
 */
function describeListing(result: OmpResultView): string[] {
  const algorithms = (result.details as { algorithms?: unknown } | undefined)?.algorithms;
  return Array.isArray(algorithms) ? [`${algorithms.length} algorithms`] : [];
}

const renderers: Readonly<Record<string, OmpRenderers>> = {
  hashes_compute: { describeCall: describeDigestCall, describeResult: describeDigest },
  hashes_hmac_compute: { describeCall: describeDigestCall, describeResult: describeDigest },
  hashes_verify: { describeCall: describeDigestCall, describeResult: describeVerdict },
  hashes_algorithms: {
    describeCall: (args) => args["algorithm"] ?? args["family"] ?? args["category"] ?? "",
    describeResult: describeListing,
  },
};

/**
 * Registers the hash tools; the executors load on the first call.
 *
 * @param pi - OMP extension API supplied by the host.
 */
export default async function hashesExtension(pi: ExtensionAPI): Promise<void> {
  pi.setLabel("Hashes");
  const { hashesTools } = await loadTools();
  registerOmpTools(pi, hashesTools, { Text, renderers });
}
