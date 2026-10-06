import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  createEventBus,
  discoverAndLoadExtensions,
  ExtensionRunner,
  ModelRegistry,
  ModelRuntime,
  SessionManager,
  type ExtensionToolContext,
  type ToolDefinition,
} from "@earendil-works/pi-coding-agent";
import { onTestFinished } from "vite-plus/test";

export interface PiTestHost {
  /** Tools the extension registered, keyed by name. */
  readonly tools: ReadonlyMap<string, ToolDefinition>;
  /** The context Pi's runner passes to `execute`. */
  readonly context: ExtensionToolContext;
  /** Returns the registered tool, or throws when the extension did not register it. */
  tool(name: string): ToolDefinition;
}

/**
 * Loads a Pi extension through Pi's own loader and runner, so a test sees the
 * registration API and execution context a real session hands out, not a
 * partial copy. The cwd, agent dir, auth file and model store it hands Pi
 * point into a temporary directory that is removed when the calling test
 * finishes, so the user's Pi extensions and credentials stay out of the test.
 *
 * Call it inside a test: the cleanup hooks into that test's lifecycle.
 *
 * @param extensionPath - Path of the extension entry, as listed under `pi.extensions`.
 * @returns {Promise<PiTestHost>} The registered tools and the execution context.
 */
export async function loadPiExtension(extensionPath: string): Promise<PiTestHost> {
  const root = mkdtempSync(join(tmpdir(), "pi-test-host-"));
  onTestFinished(() => rmSync(root, { recursive: true, force: true }));

  const loaded = await discoverAndLoadExtensions([extensionPath], root, root, createEventBus());
  const [failure] = loaded.errors;
  if (failure) {
    throw new Error(`Pi could not load ${failure.path}: ${failure.error}`);
  }

  const modelRuntime = await ModelRuntime.create({
    authPath: join(root, "auth.json"),
    modelsPath: null,
    modelsStorePath: join(root, "models"),
    refreshOnCreate: false,
  });
  const runner = new ExtensionRunner(
    loaded.extensions,
    loaded.runtime,
    root,
    SessionManager.inMemory(root),
    new ModelRegistry(modelRuntime),
  );
  const tools = new Map(
    loaded.extensions.flatMap((extension) =>
      [...extension.tools].map(([name, registered]) => [name, registered.definition] as const),
    ),
  );

  return {
    tools,
    context: runner.createToolContext("call-1", undefined),
    tool(name) {
      const tool = tools.get(name);
      if (!tool) {
        throw new Error(`The extension did not register ${name}`);
      }
      return tool;
    },
  };
}
