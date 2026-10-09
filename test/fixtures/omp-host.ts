import type {
  ExtensionAPI,
  ExtensionContext,
  Theme,
  ToolDefinition,
} from "@oh-my-pi/pi-coding-agent";

/** The adapter only wraps the JSON Schema in `Type.Unsafe`; this hands it back as it came. */
const typebox = { Type: { Unsafe: (schema: unknown) => schema } };

/**
 * Builds a test double of a host object from typed stubs. Reading a member the
 * test did not stub throws with its name, so an extension that starts using
 * another host field fails loudly instead of reading `undefined`.
 *
 * Symbol keys and `then` pass through, because `await`, Promise resolution and
 * the test runner's formatter probe them on any object.
 *
 * @param name - Label used in the error, such as `ExtensionAPI`.
 * @param stubs - The members the code under test is expected to use.
 * @returns {T} The stubs behind a proxy that rejects every other member.
 */
export function strictDouble<T extends object>(name: string, stubs: Partial<T>): T {
  return new Proxy(stubs, {
    get(target, key, receiver) {
      if (typeof key === "symbol" || key === "then" || Reflect.has(target, key)) {
        return Reflect.get(target, key, receiver);
      }
      throw new Error(`${name}.${key} is not stubbed in the OMP test host`);
    },
  }) as T;
}

export interface OmpTestHost {
  /** Tools the extension registered, keyed by name. */
  readonly tools: ReadonlyMap<string, ToolDefinition>;
  /** Labels the extension set through `setLabel`, in call order. */
  readonly labels: readonly string[];
  /** Returns the registered tool, or throws when the extension did not register it. */
  tool(name: string): ToolDefinition;
}

/**
 * Runs an OMP extension factory against a strict host double. The package
 * root cannot load under Node (it ships TypeScript inside `node_modules`), so
 * this stands in for OMP's loader with only the members the template uses:
 * the injected `typebox` facade, `setLabel` and `registerTool`.
 *
 * @param extension - The extension's default export.
 * @returns {Promise<OmpTestHost>} The registered tools and labels.
 */
export async function registerOmpExtension(
  extension: (pi: ExtensionAPI) => void | Promise<void>,
): Promise<OmpTestHost> {
  const tools = new Map<string, ToolDefinition>();
  const labels: string[] = [];

  await extension(
    strictDouble<ExtensionAPI>("ExtensionAPI", {
      typebox: typebox as unknown as ExtensionAPI["typebox"],
      setLabel(label) {
        labels.push(label);
      },
      registerTool(tool) {
        // The host keeps tools with their parameter type erased, the way a test
        // calls them: with arguments that may break the schema on purpose.
        tools.set(tool.name, tool as ToolDefinition);
      },
    }),
  );

  return {
    tools,
    labels,
    tool(name) {
      const tool = tools.get(name);
      if (!tool) {
        throw new Error(`The extension did not register ${name}`);
      }
      return tool;
    },
  };
}

/** A context with no UI and so no `ask`: a tool that reads anything else fails by name. */
export const ompToolContext = strictDouble<ExtensionContext>("ExtensionContext", {
  hasUI: false,
  ui: undefined,
});

/**
 * A theme that writes its styling calls into the output, so a renderer test
 * can assert which color and symbol went where: `fg("accent", "x")` renders as
 * `accent(x)` and `styledSymbol("status.done", "success")` as
 * `success:status.done`.
 */
export const ompTestTheme = strictDouble<Theme>("Theme", {
  fg: (color, text) => `${color}(${text})`,
  styledSymbol: (symbol, color) => `${color}:${symbol}`,
  spinnerFrames: ["frame-0", "frame-1"],
  format: strictDouble<Theme["format"]>("Theme.format", { bracketLeft: "[", bracketRight: "]" }),
  sep: strictDouble<Theme["sep"]>("Theme.sep", { dot: " | " }),
});
