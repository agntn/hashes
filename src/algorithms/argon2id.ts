import { argon2id } from "../core/argon2.ts";
import type { Argon2Parameters } from "../core/argon2.ts";
import {
  assertOneRound,
  decodeInput,
  ENCODING_OPTION,
  encodeDigest,
  guarded,
  resolveSalt,
  SALT_OPTION,
  toBytes,
  type SaltOptions,
} from "../core/digest.ts";
import { Hash, type HashAbout } from "../core/hash.ts";
import type { AlgorithmInfo, HashInput, HashOptions, HashResult } from "../core/types.ts";

/** Options Argon2 takes besides the encoding. */
export interface Argon2Options extends HashOptions, SaltOptions {
  /** Memory in KiB, at least 8 per lane. Default: 65536. */
  memory?: number;
  /** Passes over the memory. Default: 3. */
  iterations?: number;
  /** Lanes. Default: 4. */
  parallelism?: number;
  /** Output key length in bytes, at least 4. Default: 32. */
  keyLength?: number;
  /** Key K, hex in a string. Default: none. */
  secret?: string | Uint8Array;
  /** Associated data X, hex in a string. Default: none. */
  associatedData?: string | Uint8Array;
}

/**
 * Reads optional bytes given as hex in a string.
 *
 * @param value - The option as passed.
 * @param name - Its name, for the error.
 * @returns {Uint8Array} The bytes, empty when left out.
 */
function hexBytes(value: string | Uint8Array | undefined, name: string): Uint8Array {
  if (value === undefined) return new Uint8Array(0);
  return typeof value === "string" ? toBytes(decodeInput(value, "hex", name)) : value;
}

/**
 * Reads the cost and the optional inputs with their defaults.
 *
 * @param options - The Argon2 options.
 * @returns {Argon2Parameters} What the byte function takes.
 */
function argon2Parameters(options?: Readonly<Argon2Options>): Argon2Parameters {
  const { memory = 65536, iterations = 3, parallelism = 4, keyLength = 32 } = options ?? {};
  return {
    memory,
    iterations,
    parallelism,
    keyLength,
    secret: hexBytes(options?.secret, "secret"),
    associatedData: hexBytes(options?.associatedData, "associatedData"),
  };
}

/**
 * What a result reports to repeat the call. The secret stays out, since the caller holds it.
 *
 * @param parameters - The parameters the key came from.
 * @returns {Record<string, number | string>} The cost, and the associated data in hex when set.
 */
function reported(parameters: Readonly<Argon2Parameters>): Record<string, number | string> {
  const { memory, iterations, parallelism, keyLength, associatedData } = parameters;
  const shown: Record<string, number | string> = { memory, iterations, parallelism, keyLength };
  if (associatedData?.length) shown["associatedData"] = associatedData.toHex();
  return shown;
}

/** Argon2 as RFC 9106 runs it; each variant names itself and its function. */
export abstract class Argon2 extends Hash {
  protected abstract readonly about: HashAbout;

  /**
   * Runs the variant.
   *
   * @param password - The password.
   * @param salt - The salt.
   * @param parameters - Cost, output and the optional inputs.
   * @returns {Uint8Array} The derived key.
   */
  protected abstract derive(
    password: Uint8Array,
    salt: Uint8Array,
    parameters: Readonly<Argon2Parameters>,
  ): Uint8Array;

  /**
   * Describes the algorithm.
   *
   * @returns {AlgorithmInfo} Its metadata.
   */
  info(): AlgorithmInfo {
    return {
      name: this.key,
      ...this.about,
      hmac: false,
      options: [
        ENCODING_OPTION,
        SALT_OPTION,
        {
          name: "memory",
          type: "number",
          required: false,
          default: 65536,
          description: "Memory in KiB, at least 8 per lane",
        },
        {
          name: "iterations",
          type: "number",
          required: false,
          default: 3,
          description: "Passes over the memory",
        },
        { name: "parallelism", type: "number", required: false, default: 4, description: "Lanes" },
        {
          name: "keyLength",
          type: "number",
          required: false,
          default: 32,
          description: "Output key length in bytes, at least 4",
        },
        {
          name: "secret",
          type: "string",
          required: false,
          default: "",
          description: "Secret key in hex, a pepper",
        },
        {
          name: "associatedData",
          type: "string",
          required: false,
          default: "",
          description: "Associated data in hex",
        },
      ],
    };
  }

  /**
   * Derives a key from the input.
   *
   * @param input - Text or bytes.
   * @param options - Encoding, salt, cost and the optional secret and associated data.
   * @returns {HashResult} The derived key.
   */
  hash(input: HashInput, options?: Readonly<Argon2Options>): HashResult {
    return guarded(this.key, () => {
      if (options?.key !== undefined) throw new Error(`${this.key} has no HMAC mode`);
      assertOneRound(options, `${this.key} sets its cost with its own parameters`);
      const parameters = argon2Parameters(options);
      const salt = resolveSalt(options);
      const raw = this.derive(toBytes(input), salt, parameters);
      return encodeDigest(raw, this.key, "hash", options?.encoding ?? "hex", {
        ...reported(parameters),
        salt: salt.toHex(),
      });
    });
  }
}

export class Argon2id extends Argon2 {
  static readonly key = "argon2id";
  protected readonly about = {
    label: "Argon2id",
    description:
      "Argon2id (RFC 9106), memory-hard, data-independent reads for half a pass and data-dependent after",
    family: "Argon2",
    category: "password",
    securityNote:
      "The primary variant of RFC 9106. The defaults are its second recommended option, 64 MiB with 3 passes and 4 lanes; the first wants 2 GiB with 1 pass.",
  } as const;

  protected derive(password: Uint8Array, salt: Uint8Array, parameters: Readonly<Argon2Parameters>) {
    return argon2id(password, salt, parameters);
  }
}
