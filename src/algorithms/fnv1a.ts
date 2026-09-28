import { defineFixedAlgorithm } from "../core/digest.ts";

/**
 * Computes the 64-bit FNV-1a hash on two 32-bit halves. The prime is 2^40 + 0x1b3, so each step
 * multiplies the low half by 0x1b3 and adds the low half, shifted by 8, into the high half.
 *
 * @param data - Bytes to hash.
 * @returns {Uint8Array} The hash, big-endian.
 */
function fnv1a64(data: Uint8Array): Uint8Array {
  // Offset basis 0xcbf29ce484222325.
  let high = 0xcbf29ce4;
  let low = 0x84222325;
  for (const byte of data) {
    low = (low ^ byte) >>> 0;
    // Below 2^41, so the double is exact and its top bits are the carry into the high half.
    const carry = Math.floor((low * 0x1b3) / 0x1_0000_0000);
    high = (Math.imul(high, 0x1b3) + (low << 8) + carry) >>> 0;
    low = Math.imul(low, 0x1b3) >>> 0;
  }
  const digest = new Uint8Array(8);
  const view = new DataView(digest.buffer);
  view.setUint32(0, high);
  view.setUint32(4, low);
  return digest;
}

export const fnv1a = defineFixedAlgorithm({
  name: "fnv1a",
  label: "FNV-1a (64-bit)",
  description: "FNV-1a 64-bit, a simple, fast non-cryptographic hash for hash tables and dedup",
  family: "non-cryptographic",
  digestLength: 8,
  securityNote: "NOT for security: simple hash for hash tables, fingerprints, dedup",
  compute: fnv1a64,
});
