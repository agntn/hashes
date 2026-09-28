import { crc32 as zlibCrc32 } from "node:zlib";
import { defineFixedAlgorithm } from "../core/digest.ts";

export const crc32 = defineFixedAlgorithm({
  name: "crc32",
  label: "CRC-32",
  description: "CRC-32 cyclic redundancy check, used in ZIP, PNG, gzip and network protocols",
  family: "non-cryptographic",
  digestLength: 4,
  securityNote: "NOT for security: error-detection checksum only",
  compute: (bytes) => {
    const digest = new Uint8Array(4);
    new DataView(digest.buffer).setUint32(0, zlibCrc32(bytes));
    return digest;
  },
});
