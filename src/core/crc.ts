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
const CRC16_XMODEM_TABLES = /* @__PURE__ */ new Int32Array(256 * 8);
const CRC32_BZIP2_TABLES = /* @__PURE__ */ new Int32Array(256 * 8);
const CRC64_XZ_TABLES = /* @__PURE__ */ new Uint32Array(512 * 8);
const CRC24_OPENPGP_TABLES = /* @__PURE__ */ new Int32Array(256 * 8);

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
 * Fills slicing tables for an unreflected CRC held in the top bits, so CRC-24 and CRC-16 slice
 * like CRC-32/BZIP2.
 *
 * @param tables - The eight tables to fill, 256 entries each.
 * @param polynomial - The polynomial, shifted to the top of 32 bits.
 */
function fillTopTables(tables: Int32Array, polynomial: number): void {
  for (let index = 0; index < 256; index++) {
    let value = index << 24;
    for (let bit = 0; bit < 8; bit++) value = value < 0 ? (value << 1) ^ polynomial : value << 1;
    tables[index] = value;
  }
  for (let index = 0; index < 256 * 7; index++) {
    const value = tables[index]!;
    tables[index + 256] = (value << 8) ^ tables[value >>> 24]!;
  }
}

/** Fills the CRC-16/XMODEM tables: polynomial 0x1021, not reflected. */
function fillCrc16XmodemTables(): void {
  if (crc16XmodemFilled) return;
  fillTopTables(CRC16_XMODEM_TABLES, 0x10210000);
  crc16XmodemFilled = true;
}

/** Fills the CRC-32/BZIP2 tables: polynomial 0x04c11db7, not reflected. */
function fillCrc32Bzip2Tables(): void {
  if (crc32Bzip2Filled) return;
  fillTopTables(CRC32_BZIP2_TABLES, 0x04c11db7);
  crc32Bzip2Filled = true;
}

/** Fills the CRC-24/OPENPGP tables: polynomial 0x864cfb, not reflected. */
function fillCrc24OpenpgpTables(): void {
  if (crc24OpenpgpFilled) return;
  fillTopTables(CRC24_OPENPGP_TABLES, 0x864cfb00);
  crc24OpenpgpFilled = true;
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
  return put(new Uint8Array(4), 0, ~crc);
}

/**
 * Writes the top bytes of a register big-endian. A `DataView` costs a short CRC more than the CRC.
 *
 * @param digest - Where the bytes go.
 * @param offset - Index of the first one.
 * @param value - The register, its checksum in the top bits.
 * @returns {Uint8Array} The digest.
 */
function put(digest: Uint8Array, offset: number, value: number): Uint8Array {
  for (let shift = 24; offset < digest.length && shift >= 0; shift -= 8) {
    digest[offset++] = value >>> shift;
  }
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
  return put(new Uint8Array(4), 0, ~crc);
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
  return put(put(new Uint8Array(8), 0, ~high), 4, ~low);
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
  fillCrc24OpenpgpTables();
  const t = CRC24_OPENPGP_TABLES;
  const end = data.length - (data.length & 7);
  let crc = 0xb704ce00;
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
  return put(new Uint8Array(3), 0, crc);
}

/**
 * Computes CRC-16/XMODEM: polynomial 0x1021, initial value 0, no reflection, no final xor.
 *
 * @param data - Bytes the checksum covers.
 * @returns {Uint8Array} The checksum, big-endian.
 */
export function crc16Xmodem(data: Uint8Array): Uint8Array {
  assertBytes(data, "data");
  fillCrc16XmodemTables();
  const t = CRC16_XMODEM_TABLES;
  const end = data.length - (data.length & 7);
  let crc = 0;
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
  return put(new Uint8Array(2), 0, crc);
}
