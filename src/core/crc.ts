/**
 * CRC-32 (as zlib computes it, or as bzip2 does), CRC-64/XZ, CRC-24/OPENPGP and CRC-16/XMODEM.
 * Each table fills on the first call that needs it, so a SHA-1 caller loading the shared chunk
 * never pays for it.
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

/** The CRC-24 variants, by their names in the CRC catalogue. */
export const CRC24_VARIANTS = ["openpgp"] as const;

/** A CRC-24 variant. */
export type Crc24Variant = (typeof CRC24_VARIANTS)[number];

/** Allocated empty and filled on first use, since a module constant keeps the hot loops fast. */
const CRC32_TABLES = /* @__PURE__ */ new Int32Array(256 * 8);
const CRC16_XMODEM_TABLE = /* @__PURE__ */ new Uint16Array(256);
const CRC32_BZIP2_TABLES = /* @__PURE__ */ new Int32Array(256 * 8);
const CRC64_XZ_TABLES = /* @__PURE__ */ new Uint32Array(512 * 8);
const CRC24_OPENPGP_TABLE = /* @__PURE__ */ new Uint32Array(256);

let crc32Filled = false;
let crc16XmodemFilled = false;
let crc32Bzip2Filled = false;
let crc64XzFilled = false;
let crc24OpenpgpFilled = false;

/**
 * Fills the CRC-32 tables for slicing by eight: polynomial 0x04c11db7, reflected as 0xedb88320.
 * Table `k` at `256 * k` advances a byte's remainder through `k` more zero bytes.
 */
function fillCrc32Tables(): void {
  if (crc32Filled) return;
  const tables = CRC32_TABLES;
  for (let index = 0; index < 256; index++) {
    let value = index;
    for (let bit = 0; bit < 8; bit++) value = value & 1 ? (value >>> 1) ^ 0xedb88320 : value >>> 1;
    tables[index] = value;
  }
  for (let index = 0; index < 256 * 7; index++) {
    const value = tables[index]!;
    tables[index + 256] = (value >>> 8) ^ tables[value & 0xff]!;
  }
  crc32Filled = true;
}

/**
 * Fills the CRC-16/XMODEM table, each byte's remainder: polynomial 0x1021, not reflected.
 */
function fillCrc16XmodemTable(): void {
  if (crc16XmodemFilled) return;
  const table = CRC16_XMODEM_TABLE;
  for (let index = 0; index < 256; index++) {
    let value = index << 8;
    for (let bit = 0; bit < 8; bit++) {
      value = value & 0x8000 ? ((value << 1) ^ 0x1021) & 0xffff : (value << 1) & 0xffff;
    }
    table[index] = value;
  }
  crc16XmodemFilled = true;
}

/**
 * Fills the CRC-32/BZIP2 tables for slicing by eight: polynomial 0x04c11db7, not reflected.
 */
function fillCrc32Bzip2Tables(): void {
  if (crc32Bzip2Filled) return;
  const tables = CRC32_BZIP2_TABLES;
  for (let index = 0; index < 256; index++) {
    let value = index << 24;
    for (let bit = 0; bit < 8; bit++)
      value = value & 0x80000000 ? (value << 1) ^ 0x04c11db7 : value << 1;
    tables[index] = value;
  }
  for (let index = 0; index < 256 * 7; index++) {
    const value = tables[index]!;
    tables[index + 256] = (value << 8) ^ tables[value >>> 24]!;
  }
  crc32Bzip2Filled = true;
}

/**
 * Fills the CRC-64/XZ tables for slicing by eight: ECMA-182 reflected, 0xc96c5795d7870f42. Each
 * entry is a high and a low half at `2 * byte`, since BigInt would run it far slower.
 */
function fillCrc64XzTables(): void {
  if (crc64XzFilled) return;
  const tables = CRC64_XZ_TABLES;
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
    tables[2 * index] = high;
    tables[2 * index + 1] = low;
  }
  for (let index = 0; index < 512 * 7; index += 2) {
    const high = tables[index]!;
    const low = tables[index + 1]!;
    const next = 2 * (low & 0xff);
    tables[index + 512] = (high >>> 8) ^ tables[next]!;
    tables[index + 513] = ((low >>> 8) | (high << 24)) ^ tables[next + 1]!;
  }
  crc64XzFilled = true;
}

/** Fills the CRC-24/OPENPGP table, each byte's remainder: polynomial 0x864cfb, not reflected. */
function fillCrc24OpenpgpTable(): void {
  if (crc24OpenpgpFilled) return;
  const table = CRC24_OPENPGP_TABLE;
  for (let index = 0; index < 256; index++) {
    let value = index << 16;
    for (let bit = 0; bit < 8; bit++)
      value = value & 0x800000 ? (value << 1) ^ 0x1864cfb : value << 1;
    table[index] = value;
  }
  crc24OpenpgpFilled = true;
}

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
  fillCrc32Tables();
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
  fillCrc32Bzip2Tables();
  const t = CRC32_BZIP2_TABLES;
  const end = data.length - (data.length & 7);
  let crc = -1;
  let i = 0;
  for (; i < end; i += 8) {
    const high =
      crc ^ ((data[i]! << 24) | (data[i + 1]! << 16) | (data[i + 2]! << 8) | data[i + 3]!);
    crc =
      t[1792 + (high >>> 24)]! ^
      t[1536 + ((high >>> 16) & 0xff)]! ^
      t[1280 + ((high >>> 8) & 0xff)]! ^
      t[1024 + (high & 0xff)]! ^
      t[768 + data[i + 4]!]! ^
      t[512 + data[i + 5]!]! ^
      t[256 + data[i + 6]!]! ^
      t[data[i + 7]!]!;
  }
  for (; i < data.length; i++) crc = (crc << 8) ^ t[((crc >>> 24) ^ data[i]!) & 0xff]!;
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
  fillCrc64XzTables();
  const t = CRC64_XZ_TABLES;
  const end = data.length - (data.length & 7);
  let high = -1;
  let low = -1;
  let i = 0;
  for (; i < end; i += 8) {
    const first =
      low ^ (data[i]! | (data[i + 1]! << 8) | (data[i + 2]! << 16) | (data[i + 3]! << 24));
    const second =
      high ^ (data[i + 4]! | (data[i + 5]! << 8) | (data[i + 6]! << 16) | (data[i + 7]! << 24));
    const a = 3584 + 2 * (first & 0xff);
    const b = 3072 + 2 * ((first >>> 8) & 0xff);
    const c = 2560 + 2 * ((first >>> 16) & 0xff);
    const d = 2048 + 2 * (first >>> 24);
    const e = 1536 + 2 * (second & 0xff);
    const f = 1024 + 2 * ((second >>> 8) & 0xff);
    const g = 512 + 2 * ((second >>> 16) & 0xff);
    const h = 2 * (second >>> 24);
    high = t[a]! ^ t[b]! ^ t[c]! ^ t[d]! ^ t[e]! ^ t[f]! ^ t[g]! ^ t[h]!;
    low =
      t[a + 1]! ^ t[b + 1]! ^ t[c + 1]! ^ t[d + 1]! ^ t[e + 1]! ^ t[f + 1]! ^ t[g + 1]! ^ t[h + 1]!;
  }
  for (; i < data.length; i++) {
    const index = 2 * ((low ^ data[i]!) & 0xff);
    low = ((low >>> 8) | (high << 24)) ^ t[index + 1]!;
    high = (high >>> 8) ^ t[index]!;
  }
  const digest = new Uint8Array(8);
  const view = new DataView(digest.buffer);
  view.setInt32(0, ~high);
  view.setInt32(4, ~low);
  return digest;
}

/**
 * Computes CRC-24: `openpgp`, the checksum after the `=` that closes OpenPGP armor (RFC 4880).
 *
 * @param data - Bytes to check.
 * @param variant - Which CRC-24. Default: `openpgp`.
 * @returns {Uint8Array} The checksum, big-endian, as armor stores it.
 */
export function crc24(data: Uint8Array, variant: Crc24Variant = "openpgp"): Uint8Array {
  assertBytes(data, "data");
  if (variant !== "openpgp") {
    throw new InvalidOptionError("variant", variant, `use one of ${CRC24_VARIANTS.join(", ")}`);
  }
  fillCrc24OpenpgpTable();
  const table = CRC24_OPENPGP_TABLE;
  let crc = 0xb704ce;
  for (const byte of data) crc = ((crc << 8) & 0xffffff) ^ table[((crc >>> 16) ^ byte) & 0xff]!;
  return new Uint8Array([crc >>> 16, (crc >>> 8) & 0xff, crc & 0xff]);
}

/**
 * Computes CRC-16/XMODEM: polynomial 0x1021, initial value 0, no reflection, no final xor.
 *
 * @param data - Bytes the checksum covers.
 * @returns {Uint8Array} The checksum, big-endian.
 */
export function crc16Xmodem(data: Uint8Array): Uint8Array {
  assertBytes(data, "data");
  fillCrc16XmodemTable();
  const table = CRC16_XMODEM_TABLE;
  let crc = 0;
  for (const byte of data) crc = ((crc << 8) & 0xffff) ^ table[((crc >>> 8) ^ byte) & 0xff]!;
  return new Uint8Array([crc >>> 8, crc & 0xff]);
}
