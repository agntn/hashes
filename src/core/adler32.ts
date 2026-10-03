/** Adler-32 from RFC 1950, the checksum that closes a zlib stream. */
import { assertBytes } from "./hasher.ts";

/** Largest prime below 2^16. */
const BASE = 65521;

/** Most bytes summed between reductions, zlib's NMAX: both sums stay below 2^32. */
const RUN = 5552;

/**
 * Computes Adler-32: two sums modulo 65521, the first of the bytes plus one, the second of the
 * first after each byte.
 *
 * @param data - Bytes to check.
 * @returns {Uint8Array} The checksum, big-endian, as zlib writes it.
 */
export function adler32(data: Uint8Array): Uint8Array {
  assertBytes(data, "data");
  let a = 1;
  let b = 0;
  for (let start = 0; start < data.length; start += RUN) {
    const end = Math.min(start + RUN, data.length);
    for (let i = start; i < end; i++) {
      a += data[i]!;
      b += a;
    }
    a %= BASE;
    b %= BASE;
  }
  const digest = new Uint8Array(4);
  new DataView(digest.buffer).setUint32(0, ((b << 16) | a) >>> 0);
  return digest;
}
