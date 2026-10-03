/**
 * Outputs of independent implementations for the compression checksums, frozen so the tests need
 * no Python. Made with CPython 3.12.13 `zlib.adler32`, crccheck 1.3.1 (`Crc32Bzip2`, `Crc64Xz`)
 * and the xxhash 4.0.1 binding of the reference C library (`xxh32`, `xxh64`).
 *
 * Each row is a length, then Adler-32, CRC-32/BZIP2, CRC-64/XZ, XXH32, XXH32 with seed 0xdeadbeef
 * and XXH64, in hex, of `checksumInput(length)`.
 */
export const CHECKSUM_REFERENCES = [
  [0, "00000001", "00000000", "0000000000000000", "02cc5d05", "c372c6cb", "ef46db3751d8e999"],
  [1, "008d008d", "edf73bc1", "5ab0b26bb371d24e", "164eea5d", "ce5c70ac", "5e7901b3cf7c2ea4"],
  [3, "0215017b", "7ccc5194", "5831917491ab8e8f", "09d2ee3e", "887326f8", "27fef228fd79c02e"],
  [4, "051001e6", "d75a051f", "d77888ca2f8cc249", "6413858a", "fabf1445", "e07c670c54f837cd"],
  [5, "0a5b0346", "cd851349", "7864a1022155e71f", "d909ec4c", "8aca7905", "8224461d9fedfc5c"],
  [15, "4532083a", "daaf917c", "5b2ee25361b300f0", "e825bc91", "c7d8c58f", "ce38bbce4310be91"],
  [16, "44600789", "cea67d7b", "8bfbf0f082031d26", "2030c43e", "d4eeebc4", "dfdca3cf28c8f3c9"],
  [17, "5d3d0a27", "ae956553", "16f135a4ead006d0", "ecc1b200", "9a36634f", "62d960c0725680f6"],
  [31, "01a80ec6", "e965c8b8", "9fa1a192ca565f4a", "500c8af7", "11b21031", "fcf89eb5c85add50"],
  [32, "105410b5", "9ab4d1a2", "4405e36559449035", "40946f58", "3dbdf15d", "a601809d8d34a7b6"],
  [33, "34fb11c4", "b8f12907", "a3f551f96974609a", "2ad0e88f", "5d8844ec", "089fbc1eaba27dc8"],
  [63, "48c722b7", "23d02081", "a739e60833c531a4", "40b19727", "490e204a", "d236b15110047742"],
  [64, "d0c11f21", "96cc5ffb", "9c239e647d100d4d", "37352650", "87a2c203", "634ec8f60763cd9b"],
  [65, "64612056", "5e41dc6b", "c9f4d6be63e4d8dc", "9a5fcfc3", "f457e07e", "fe510b1e6d3e3706"],
  [100, "83192cef", "f0711ce7", "a9a44e48000efa40", "ece79c3c", "0ceedb5d", "1b11804e06d5c5d2"],
  [1000, "c2a9fb35", "f59d54a1", "0d41cbf4685cff66", "ab85eda4", "cc6535dc", "a9215845f780fdac"],
  [5552, "8ac5e747", "bcd9e1e3", "ad1a16cbd200aa40", "8162f80c", "4bf7e0ad", "ff7270d1825581ad"],
  [5553, "411bb6ed", "628c3339", "70c08b1ac5af9122", "bb73d080", "5c16ecb2", "faffbd3643247dee"],
  [65537, "fb105ebf", "d469cf8c", "9df9844b1719f14e", "5bf1d2fa", "773a1665", "b153aa201990e2c9"],
] as const;

/**
 * The bytes each reference row covers: glibc's old `rand` LCG seeded with `length + 1`, one byte
 * from bits 16 to 23 of each state.
 *
 * @param length - How many bytes.
 * @returns {Uint8Array} The input.
 */
export function checksumInput(length: number): Uint8Array {
  const bytes = new Uint8Array(length);
  let state = length + 1;
  for (let index = 0; index < length; index++) {
    state = (Math.imul(state, 1103515245) + 12345) & 0x7fffffff;
    bytes[index] = (state >>> 16) & 0xff;
  }
  return bytes;
}
