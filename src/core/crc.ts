/**
 * CRC-32 as zlib computes it and CRC-16/XMODEM. The lookup tables are built on first import of
 * this module; the builders are marked pure so a bundle that never calls a CRC drops them.
 */
import { assertBytes } from "./hasher.ts";

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

const CRC32_TABLES = /* @__PURE__ */ crc32Tables();
const CRC16_XMODEM_TABLE = /* @__PURE__ */ crc16XmodemTable();

/**
 * Computes CRC-32 as zlib does: initial value and final xor all ones.
 *
 * @param data - Bytes to check.
 * @returns {Uint8Array} The checksum, big-endian.
 */
export function crc32(data: Uint8Array): Uint8Array {
  assertBytes(data, "data");
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
