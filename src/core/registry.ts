import { builtins } from "../algorithms/index.ts";
import { UnknownAlgorithmError } from "./errors.ts";
import type { Hash, HashConstructor } from "./hash.ts";

let classes: Map<string, HashConstructor> | undefined;
const instances = new Map<string, Hash>();

/**
 * The class map, seeded with the built-ins on first use. Importing the package mutates no
 * shared state, which is what `sideEffects: false` promises; the algorithm modules themselves
 * are still imported with the package.
 *
 * @returns {Map<string, HashConstructor>} Registered classes by key.
 */
function registry(): Map<string, HashConstructor> {
  classes ??= new Map(builtins.map((HashClass) => [HashClass.key, HashClass] as const));
  return classes;
}

/**
 * Registers a hash algorithm class under its `key`, replacing any algorithm with the same key.
 *
 * @param HashClass - The class, with a static `key`.
 */
export function register(HashClass: HashConstructor): void {
  registry().set(HashClass.key, HashClass);
  instances.delete(HashClass.key);
}

/**
 * Creates a hash algorithm by exact key, cached per key.
 *
 * @param name - Exact registry key.
 * @returns {Hash} The cached algorithm instance.
 */
export function create(name: string): Hash {
  const cached = instances.get(name);
  if (cached) return cached;
  const HashClass = registry().get(name);
  if (!HashClass) throw new UnknownAlgorithmError(name, algorithms());
  const algorithm = new HashClass();
  instances.set(name, algorithm);
  return algorithm;
}

/**
 * Lists the registered algorithm keys: the built-ins in listing order, then registrations.
 *
 * @returns {string[]} Registered keys.
 */
export function algorithms(): string[] {
  return [...registry().keys()];
}

/**
 * Checks whether an algorithm is registered.
 *
 * @param name - Exact registry key.
 * @returns {boolean} Whether the key is registered.
 */
export function has(name: string): boolean {
  return registry().has(name);
}
