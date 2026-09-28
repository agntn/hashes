import { encodeDigest, guarded, toBytes } from "../core/digest.ts";
import { ENCODING_OPTION } from "../core/noble.ts";
import type { AlgorithmEntry, HashAlgorithm, HashInput, HashOptions } from "../core/types.ts";

/** FNV-1a 64-bit parameters. */
const FNV64_OFFSET = 0xcbf29ce484222325n;
const FNV64_PRIME = 0x100000001b3n;
const MASK64 = 0xffffffffffffffffn;

/**
 * Computes the 64-bit FNV-1a hash.
 *
 * @param data - Bytes to hash.
 * @returns {bigint} The unsigned 64-bit hash.
 */
function fnv1a64(data: Uint8Array): bigint {
  let hash = FNV64_OFFSET;
  for (const byte of data) {
    hash = ((hash ^ BigInt(byte)) * FNV64_PRIME) & MASK64;
  }
  return hash;
}

const algorithm: HashAlgorithm = {
  name: () => "fnv1a",
  info: () => ({
    name: "fnv1a",
    label: "FNV-1a (64-bit)",
    description: "FNV-1a 64-bit, a simple, fast non-cryptographic hash for hash tables and dedup",
    family: "non-cryptographic",
    digestLength: 8,
    hmac: false,
    options: [ENCODING_OPTION],
    securityNote: "NOT for security: simple hash for hash tables, fingerprints, dedup",
  }),
  hash: (input: HashInput, options?: Readonly<HashOptions>) =>
    guarded("fnv1a", () => {
      const raw = Buffer.alloc(8);
      raw.writeBigUInt64BE(fnv1a64(toBytes(input)));
      return encodeDigest(new Uint8Array(raw), "fnv1a", "hash", options?.encoding ?? "hex");
    }),
};

export const fnv1a: AlgorithmEntry = { name: "fnv1a", create: () => algorithm };
