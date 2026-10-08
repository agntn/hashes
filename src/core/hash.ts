import type { AlgorithmInfo, HashInput, HashOptions, HashResult } from "./types.ts";

/** A hash algorithm class the registry can create. */
export interface HashConstructor {
  /** Registry name, lowercase kebab-case. */
  readonly key: string;
  new (): Hash;
}

/** Base class for all hash algorithms. */
export abstract class Hash {
  /**
   * Registry name, read from the class.
   *
   * @returns {string} The static `key` of the concrete class.
   */
  get key(): string {
    return (this.constructor as HashConstructor).key;
  }

  /**
   * Returns the registry name.
   *
   * @returns {string} The algorithm's key.
   */
  name(): string {
    return this.key;
  }

  /** Return metadata describing the algorithm. */
  abstract info(): AlgorithmInfo;

  /** Compute the hash (or HMAC) of the input. */
  abstract hash(input: HashInput, options?: HashOptions): HashResult;

  /**
   * Hashes every input with the same options, in order, a KDF drawing a fresh salt for each.
   *
   * @param inputs - Text or bytes, one entry per digest.
   * @param options - What `hash` takes, shared by every input.
   * @returns {HashResult[]} One result per input.
   */
  hashMany(inputs: readonly HashInput[], options?: Parameters<this["hash"]>[1]): HashResult[] {
    return inputs.map((input) => this.hash(input, options));
  }
}

/** What an algorithm tells about itself besides its name, options and HMAC support. */
export type HashAbout = Pick<
  AlgorithmInfo,
  "label" | "description" | "family" | "category" | "digestLength" | "securityNote"
>;
