import { existsSync } from "node:fs";
import { fileURLToPath } from "node:url";

import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";
import { registerPiTools } from "@agntn/tools/pi";

import type * as HashTools from "../../../dist/tools.d.mts";

const sourceModuleUrl = new URL("../../../src/tools.ts", import.meta.url);
const distributionModuleUrl = new URL("../../../dist/tools.mjs", import.meta.url);

/**
 * Registers the hash tools, from the source in a checkout and the build in the package.
 *
 * @param pi - Pi extension API.
 */
export default async function hashesExtension(pi: ExtensionAPI): Promise<void> {
  const { hashesTools } = (await import(
    existsSync(fileURLToPath(sourceModuleUrl)) ? sourceModuleUrl.href : distributionModuleUrl.href
  )) as typeof HashTools;
  registerPiTools(pi, hashesTools);
}
