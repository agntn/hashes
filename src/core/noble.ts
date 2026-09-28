import { hmac } from "@noble/hashes/hmac.js";
import type { CHash } from "@noble/hashes/utils.js";
import { encodeDigest, guarded, toBytes } from "./digest.ts";
import type {
  AlgorithmEntry,
  AlgorithmInfo,
  HashAlgorithm,
  HashFamily,
  HashInput,
  HashOption,
  HashOptions,
  HashResult,
} from "./types.ts";

/** Everything that tells one @noble/hashes-backed algorithm from another. */
export interface NobleAlgorithmDefinition {
  name: string;
  label: string;
  description: string;
  family: HashFamily;
  /** The noble hash, such as `sha256` or `blake2b`. */
  hashFn: CHash;
  digestLength?: number;
  /** Whether HMAC mode is offered. Default: true. */
  hmac?: boolean;
  securityNote?: string;
  options?: HashOption[];
}

export const ENCODING_OPTION: HashOption = {
  name: "encoding",
  type: "string",
  required: false,
  default: "hex",
  description: "Output encoding: hex, base64, base64url, binary",
};

const KEY_OPTION: HashOption = {
  name: "key",
  type: "string",
  required: false,
  description: "HMAC key; enables HMAC mode",
};

/**
 * Builds a hash algorithm over a @noble/hashes function, with HMAC through `@noble/hashes/hmac`.
 *
 * @param definition - The algorithm's metadata and noble hash.
 * @returns {HashAlgorithm} The algorithm.
 */
export function makeNobleAlgorithm(definition: NobleAlgorithmDefinition): HashAlgorithm {
  const hmacSupported = definition.hmac ?? true;
  return {
    name: () => definition.name,
    info: (): AlgorithmInfo => ({
      name: definition.name,
      label: definition.label,
      description: definition.description,
      family: definition.family,
      ...(definition.digestLength === undefined ? {} : { digestLength: definition.digestLength }),
      hmac: hmacSupported,
      options: [
        ENCODING_OPTION,
        ...(hmacSupported ? [KEY_OPTION] : []),
        ...(definition.options ?? []),
      ],
      ...(definition.securityNote === undefined ? {} : { securityNote: definition.securityNote }),
    }),
    hash: (input: HashInput, options?: HashOptions): HashResult =>
      guarded(definition.name, () => {
        const data = toBytes(input);
        const encoding = options?.encoding ?? "hex";
        if (options?.key === undefined) {
          return encodeDigest(definition.hashFn(data), definition.name, "hash", encoding);
        }
        if (!hmacSupported) {
          throw new Error(`${definition.name} has no HMAC mode`);
        }
        const raw = hmac(definition.hashFn, toBytes(options.key), data);
        return encodeDigest(raw, definition.name, "hmac", encoding, { hmac: true });
      }),
  };
}

/**
 * Declares a built-in noble-backed algorithm for the registry to seed.
 *
 * @param definition - The algorithm's metadata and noble hash.
 * @returns {AlgorithmEntry} The registry entry.
 */
export function defineNobleAlgorithm(definition: NobleAlgorithmDefinition): AlgorithmEntry {
  return { name: definition.name, create: () => makeNobleAlgorithm(definition) };
}
