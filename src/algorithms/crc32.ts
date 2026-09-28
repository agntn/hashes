import { encodeDigest, guarded, toBytes } from "../core/digest.ts";
import { ENCODING_OPTION } from "../core/noble.ts";
import type { AlgorithmEntry, HashAlgorithm, HashInput, HashOptions } from "../core/types.ts";

/** CRC-32 lookup table (reflected polynomial 0xEDB88320). */
const TABLE = new Uint32Array(256);
for (let index = 0; index < 256; index++) {
  let value = index;
  for (let bit = 0; bit < 8; bit++) {
    value = value & 1 ? 0xedb88320 ^ (value >>> 1) : value >>> 1;
  }
  TABLE[index] = value;
}

/**
 * Computes the CRC-32 checksum used by ZIP, PNG and gzip.
 *
 * @param data - Bytes to check.
 * @returns {number} The unsigned 32-bit checksum.
 */
function crc32Compute(data: Uint8Array): number {
  let crc = 0xffffffff;
  for (const byte of data) {
    crc = TABLE[(crc ^ byte) & 0xff]! ^ (crc >>> 8);
  }
  return (crc ^ 0xffffffff) >>> 0;
}

const algorithm: HashAlgorithm = {
  name: () => "crc32",
  info: () => ({
    name: "crc32",
    label: "CRC-32",
    description: "CRC-32 cyclic redundancy check, used in ZIP, PNG, gzip and network protocols",
    family: "non-cryptographic",
    digestLength: 4,
    hmac: false,
    options: [ENCODING_OPTION],
    securityNote: "NOT for security: error-detection checksum only",
  }),
  hash: (input: HashInput, options?: Readonly<HashOptions>) =>
    guarded("crc32", () => {
      const raw = Buffer.alloc(4);
      raw.writeUInt32BE(crc32Compute(toBytes(input)));
      return encodeDigest(new Uint8Array(raw), "crc32", "hash", options?.encoding ?? "hex");
    }),
};

export const crc32: AlgorithmEntry = { name: "crc32", create: () => algorithm };
