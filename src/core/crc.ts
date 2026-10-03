/**
 * CRC-32 (as zlib computes it, or as bzip2 does), CRC-64/XZ and CRC-16/XMODEM. The lookup tables
 * are built on first import of this module; the builders are marked pure so a bundle that never
 * calls a CRC drops them.
 */
import { InvalidOptionError } from "./errors.ts";
import { assertBytes } from "./hasher.ts";

/** The CRC-32 variants, by their names in the CRC catalogue: zlib's first, then bzip2's. */
export const CRC32_VARIANTS = ["iso-hdlc", "bzip2"] as const;

/** A CRC-32 variant. */
export type Crc32Variant = (typeof CRC32_VARIANTS)[number];

/** The CRC-64 variants, by their names in the CRC catalogue. */
export const CRC64_VARIANTS = ["xz"] as const;

/** A CRC-64 variant. */
export type Crc64Variant = (typeof CRC64_VARIANTS)[number];

/**
 * Builds the CRC-32 lookup tables for slicing by eight: polynomial 0x04c11db7, reflected as
 * 0xedb88320. Table `k` at `256 * k` advances a byte's remainder through `k` more zero bytes.
 *
 * @returns {Int32Array} Eight tables of 256 entries, one after another.
 */
function crc32Tables(): Int32Array {
  const tables = new Int32Array(256 * 8);
  for (let index = 0; index < 256; index++) {
    let value = index;
    for (let bit = 0; bit < 8; bit++) value = value & 1 ? (value >>> 1) ^ 0xedb88320 : value >>> 1;
    tables[index] = value;
  }
  for (let index = 0; index < 256 * 7; index++) {
    const value = tables[index]!;
    tables[index + 256] = (value >>> 8) ^ tables[value & 0xff]!;
  }
  return tables;
}

/**
 * Builds the CRC-16/XMODEM lookup table: polynomial 0x1021, not reflected.
 *
 * @returns {Uint16Array} The remainder of each byte.
 */
function crc16XmodemTable(): Uint16Array {
  const table = new Uint16Array(256);
  for (let index = 0; index < 256; index++) {
    let value = index << 8;
    for (let bit = 0; bit < 8; bit++) {
      value = value & 0x8000 ? ((value << 1) ^ 0x1021) & 0xffff : (value << 1) & 0xffff;
    }
    table[index] = value;
  }
  return table;
}

/**
 * Builds the CRC-32/BZIP2 lookup table: polynomial 0x04c11db7, not reflected.
 *
 * @returns {Int32Array} The remainder of each byte, in the top byte first.
 */
function crc32Bzip2Table(): Int32Array {
  const table = new Int32Array(256);
  for (let index = 0; index < 256; index++) {
    let value = index << 24;
    for (let bit = 0; bit < 8; bit++)
      value = value & 0x80000000 ? (value << 1) ^ 0x04c11db7 : value << 1;
    table[index] = value;
  }
  return table;
}

/**
 * Builds the CRC-64/XZ lookup table: polynomial 0x42f0e1eba9ea3693 (ECMA-182), reflected as
 * 0xc96c5795d7870f42. Each entry is a high and a low half, since BigInt would run it far slower.
 *
 * @returns {Uint32Array} The high half of each byte's remainder at `2 * byte`, the low at `2 * byte + 1`.
 */
function crc64XzTable(): Uint32Array {
  const table = new Uint32Array(512);
  for (let index = 0; index < 256; index++) {
    let high = 0;
    let low = index;
    for (let bit = 0; bit < 8; bit++) {
      const odd = low & 1;
      low = (low >>> 1) | (high << 31);
      high >>>= 1;
      if (odd) {
        high ^= 0xc96c5795;
        low ^= 0xd7870f42;
      }
    }
    table[2 * index] = high;
    table[2 * index + 1] = low;
  }
  return table;
}

const CRC32_TABLES = /* @__PURE__ */ crc32Tables();
const CRC32_BZIP2_TABLE = /* @__PURE__ */ crc32Bzip2Table();
const CRC64_XZ_TABLE = /* @__PURE__ */ crc64XzTable();
const CRC16_XMODEM_TABLE = /* @__PURE__ */ crc16XmodemTable();

/**
 * Computes CRC-32: `iso-hdlc`, the reflected one zlib, gzip, ZIP and PNG use, or `bzip2`, the same
 * polynomial unreflected. Both start and finish with all ones.
 *
 * @param data - Bytes to check.
 * @param variant - Which CRC-32. Default: `iso-hdlc`.
 * @returns {Uint8Array} The checksum, big-endian.
 */
export function crc32(data: Uint8Array, variant: Crc32Variant = "iso-hdlc"): Uint8Array {
  assertBytes(data, "data");
  if (variant === "bzip2") return crc32Bzip2(data);
  if (variant !== "iso-hdlc") {
    throw new InvalidOptionError("variant", variant, `use one of ${CRC32_VARIANTS.join(", ")}`);
  }
  const t = CRC32_TABLES;
  const end = data.length - (data.length & 7);
  let crc = -1;
  let i = 0;
  for (; i < end; i += 8) {
    const low =
      crc ^ (data[i]! | (data[i + 1]! << 8) | (data[i + 2]! << 16) | (data[i + 3]! << 24));
    crc =
      t[1792 + (low & 0xff)]! ^
      t[1536 + ((low >>> 8) & 0xff)]! ^
      t[1280 + ((low >>> 16) & 0xff)]! ^
      t[1024 + (low >>> 24)]! ^
      t[768 + data[i + 4]!]! ^
      t[512 + data[i + 5]!]! ^
      t[256 + data[i + 6]!]! ^
      t[data[i + 7]!]!;
  }
  for (; i < data.length; i++) crc = (crc >>> 8) ^ t[(crc ^ data[i]!) & 0xff]!;
  const digest = new Uint8Array(4);
  new DataView(digest.buffer).setInt32(0, ~crc);
  return digest;
}

/**
 * Computes CRC-32/BZIP2, the CRC bzip2 stores per block.
 *
 * @param data - Bytes to check.
 * @returns {Uint8Array} The checksum, big-endian.
 */
function crc32Bzip2(data: Uint8Array): Uint8Array {
  const table = CRC32_BZIP2_TABLE;
  let crc = -1;
  for (const byte of data) crc = (crc << 8) ^ table[((crc >>> 24) ^ byte) & 0xff]!;
  const digest = new Uint8Array(4);
  new DataView(digest.buffer).setInt32(0, ~crc);
  return digest;
}

/**
 * Computes CRC-64: `xz`, the check xz writes by default, ECMA-182 reflected, starting and
 * finishing with all ones.
 *
 * @param data - Bytes to check.
 * @param variant - Which CRC-64. Default: `xz`.
 * @returns {Uint8Array} The checksum, big-endian.
 */
export function crc64(data: Uint8Array, variant: Crc64Variant = "xz"): Uint8Array {
  assertBytes(data, "data");
  if (variant !== "xz") {
    throw new InvalidOptionError("variant", variant, `use one of ${CRC64_VARIANTS.join(", ")}`);
  }
  const table = CRC64_XZ_TABLE;
  let high = -1;
  let low = -1;
  for (const byte of data) {
    const index = 2 * ((low ^ byte) & 0xff);
    low = ((low >>> 8) | (high << 24)) ^ table[index + 1]!;
    high = (high >>> 8) ^ table[index]!;
  }
  const digest = new Uint8Array(8);
  const view = new DataView(digest.buffer);
  view.setInt32(0, ~high);
  view.setInt32(4, ~low);
  return digest;
}

/**
 * Computes CRC-16/XMODEM: polynomial 0x1021, initial value 0, no reflection, no final xor.
 *
 * @param data - Bytes the checksum covers.
 * @returns {Uint8Array} The checksum, big-endian.
 */
export function crc16Xmodem(data: Uint8Array): Uint8Array {
  assertBytes(data, "data");
  const table = CRC16_XMODEM_TABLE;
  let crc = 0;
  for (const byte of data) crc = ((crc << 8) & 0xffff) ^ table[((crc >>> 8) ^ byte) & 0xff]!;
  return new Uint8Array([crc >>> 8, crc & 0xff]);
}
