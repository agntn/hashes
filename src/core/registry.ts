import { builtins } from "../algorithms/index.ts";
import { UnknownAlgorithmError } from "./errors.ts";
import type { HashAlgorithm, HashAlgorithmFactory } from "./types.ts";

let factories: Map<string, HashAlgorithmFactory> | undefined;
const instances = new Map<string, HashAlgorithm>();

/**
 * The factory map, seeded with the built-ins on first use. Importing the package mutates no
 * shared state, which is what `sideEffects: false` promises; the algorithm modules themselves
 * are still imported with the package.
 *
 * @returns {Map<string, HashAlgorithmFactory>} Registered factories by name.
 */
function registry(): Map<string, HashAlgorithmFactory> {
  factories ??= new Map(builtins.map((entry) => [entry.name, entry.create] as const));
  return factories;
}

/**
 * Registers a hash algorithm factory, replacing any algorithm under the same name.
 *
 * @param name - Exact registry name.
 * @param factory - Creates the algorithm.
 */
export function register(name: string, factory: HashAlgorithmFactory): void {
  registry().set(name, factory);
  instances.delete(name);
}

/**
 * Creates a hash algorithm by exact name, cached per name.
 *
 * @param name - Exact registry name.
 * @returns {HashAlgorithm} The cached algorithm instance.
 */
export function create(name: string): HashAlgorithm {
  const cached = instances.get(name);
  if (cached) return cached;
  const factory = registry().get(name);
  if (!factory) throw new UnknownAlgorithmError(name, algorithms());
  const algorithm = factory();
  instances.set(name, algorithm);
  return algorithm;
}

/**
 * Lists the registered algorithm names: the built-ins in listing order, then registrations.
 *
 * @returns {string[]} Registered names.
 */
export function algorithms(): string[] {
  return [...registry().keys()];
}

/**
 * Checks whether an algorithm is registered.
 *
 * @param name - Exact registry name.
 * @returns {boolean} Whether the name is registered.
 */
export function has(name: string): boolean {
  return registry().has(name);
}
