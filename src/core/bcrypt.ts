/**
 * bcrypt (Provos and Mazières, 1999) as OpenBSD's `$2b$` runs it: the expensive EksBlowfish key
 * schedule, then `OrpheanBeholderScryDoubt` encrypted 64 times. The state is one `Uint32Array`:
 * the 18 subkeys of the P-array first, then the four S-boxes of 256 words.
 */
import { InvalidOptionError } from "./errors.ts";
import { assertBytes } from "./hasher.ts";

/** Words in the P-array, and the four S-boxes after it. */
const P_WORDS = 18;
const STATE_WORDS = P_WORDS + 4 * 256;
const S1 = P_WORDS + 256;
const S2 = P_WORDS + 512;
const S3 = P_WORDS + 768;

/** Salt bytes bcrypt takes, and the password bytes it reads before it stops. */
export const BCRYPT_SALT_LENGTH = 16;
export const BCRYPT_MAX_PASSWORD = 72;
/** The cost range OpenBSD accepts, as the base-2 logarithm of the rounds. */
export const BCRYPT_MIN_COST = 4;
export const BCRYPT_MAX_COST = 31;
/** Bytes of the result: the `$2b$` string encodes 23 of the 24 it encrypts. */
const OUTPUT_LENGTH = 23;

let piWords: Uint32Array | undefined;

/**
 * Computes Blowfish's π words once with Machin's formula, instead of shipping 8336 hex digits.
 *
 * @returns {Uint32Array} 1042 words, `0x243f6a88` first.
 */
function blowfishPi(): Uint32Array {
  if (piWords) return piWords;
  const bits = BigInt(32 * STATE_WORDS + 64);
  const one = 1n << bits;
  const arctanInverse = (x: bigint): bigint => {
    let power = one / x;
    let sum = power;
    for (let n = 3n, sign = -1n; power !== 0n; n += 2n, sign = -sign) {
      power /= x * x;
      sum += (sign * power) / n;
    }
    return sum;
  };
  const pi = 16n * arctanInverse(5n) - 4n * arctanInverse(239n);
  const fraction = (pi - (3n << bits)) >> 64n;
  const hex = fraction.toString(16).padStart(8 * STATE_WORDS, "0");
  piWords = new Uint32Array(STATE_WORDS);
  for (let i = 0; i < STATE_WORDS; i++)
    piWords[i] = Number.parseInt(hex.slice(8 * i, 8 * i + 8), 16);
  return piWords;
}

/**
 * Reads bytes as a cyclic stream of big-endian words, as Blowfish's `stream2word` does.
 *
 * @param bytes - The bytes, at least one.
 * @param count - Words to read.
 * @returns {Uint32Array} The words.
 */
function streamWords(bytes: Uint8Array, count: number): Uint32Array {
  const words = new Uint32Array(count);
  for (let i = 0, j = 0; i < count; i++) {
    let word = 0;
    for (let k = 0; k < 4; k++, j = (j + 1) % bytes.length) word = (word << 8) | bytes[j]!;
    words[i] = word;
  }
  return words;
}

/**
 * Encrypts one block with the sixteen Blowfish rounds.
 *
 * @param state - P-array and S-boxes.
 * @param block - The words, the block's left half at `at` and its right half after it.
 * @param at - Where the block starts.
 */
function encipher(state: Uint32Array, block: Uint32Array, at: number): void {
  let left = block[at]! ^ state[0]!;
  let right = block[at + 1]!;
  for (let i = 1; i < 17; i += 2) {
    right ^=
      (((state[P_WORDS + (left >>> 24)]! + state[S1 + ((left >>> 16) & 0xff)]!) ^
        state[S2 + ((left >>> 8) & 0xff)]!) +
        state[S3 + (left & 0xff)]!) ^
      state[i]!;
    left ^=
      (((state[P_WORDS + (right >>> 24)]! + state[S1 + ((right >>> 16) & 0xff)]!) ^
        state[S2 + ((right >>> 8) & 0xff)]!) +
        state[S3 + (right & 0xff)]!) ^
      state[i + 1]!;
  }
  block[at] = right ^ state[17]!;
  block[at + 1] = left;
}

/**
 * Mixes a key into the P-array, then rewrites the state by encrypting a block salted each step.
 *
 * @param state - P-array and S-boxes, rewritten in place.
 * @param key - Eighteen key words.
 * @param salt - Four salt words, all zero for the rounds that take no salt.
 */
function expandState(state: Uint32Array, key: Uint32Array, salt: Uint32Array): void {
  for (let i = 0; i < P_WORDS; i++) state[i] = state[i]! ^ key[i]!;
  const block = new Uint32Array(2);
  for (let i = 0; i < STATE_WORDS; i += 2) {
    block[0] = block[0]! ^ salt[i & 3]!;
    block[1] = block[1]! ^ salt[(i + 1) & 3]!;
    encipher(state, block, 0);
    state[i] = block[0];
    state[i + 1] = block[1];
  }
}

/**
 * Checks the salt and the cost before any work.
 *
 * @param salt - The salt.
 * @param cost - The cost.
 */
function assertParameters(salt: Uint8Array, cost: number): void {
  if (salt.length !== BCRYPT_SALT_LENGTH) {
    throw new InvalidOptionError("salt", salt.toHex(), `must be ${BCRYPT_SALT_LENGTH} bytes`);
  }
  if (!Number.isInteger(cost) || cost < BCRYPT_MIN_COST || cost > BCRYPT_MAX_COST) {
    throw new InvalidOptionError(
      "cost",
      cost,
      `must be an integer from ${BCRYPT_MIN_COST} to ${BCRYPT_MAX_COST}`,
    );
  }
}

/**
 * Hashes a password with bcrypt, refusing one past 72 bytes that `$2b$` would silently cut.
 *
 * @param password - The password.
 * @param salt - 16 bytes of salt.
 * @param cost - Base-2 logarithm of the rounds, 4 to 31.
 * @returns {Uint8Array} The 23 bytes a `$2b$` string encodes after its salt.
 */
export function bcrypt(password: Uint8Array, salt: Uint8Array, cost: number): Uint8Array {
  assertBytes(password, "password");
  assertBytes(salt, "salt");
  assertParameters(salt, cost);
  if (password.length > BCRYPT_MAX_PASSWORD) {
    throw new InvalidOptionError(
      "password",
      `${password.length} bytes`,
      `bcrypt reads at most ${BCRYPT_MAX_PASSWORD} bytes and would ignore the rest`,
    );
  }
  const keyBytes = new Uint8Array(password.length + 1);
  keyBytes.set(password);
  const key = streamWords(keyBytes, P_WORDS);
  const saltWords = streamWords(salt, 4);
  const saltKey = streamWords(salt, P_WORDS);
  const none = new Uint32Array(4);
  const state = blowfishPi().slice();
  expandState(state, key, saltWords);
  for (let round = 2 ** cost; round > 0; round--) {
    expandState(state, key, none);
    expandState(state, saltKey, none);
  }
  const text = streamWords(new TextEncoder().encode("OrpheanBeholderScryDoubt"), 6);
  for (let at = 0; at < 6; at += 2) {
    for (let i = 0; i < 64; i++) encipher(state, text, at);
  }
  const output = new Uint8Array(4 * text.length);
  const view = new DataView(output.buffer);
  for (let i = 0; i < text.length; i++) view.setUint32(4 * i, text[i]!);
  return output.slice(0, OUTPUT_LENGTH);
}

/** The base64 alphabet bcrypt writes, in its own order and without padding. */
const ALPHABET = "./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

/**
 * Encodes bytes in bcrypt's base64, the last digit carrying the bits that are left.
 *
 * @param bytes - The bytes.
 * @returns {string} The text, four digits per three bytes.
 */
function base64(bytes: Uint8Array): string {
  let text = "";
  let buffer = 0;
  let bits = 0;
  for (const byte of bytes) {
    buffer = ((buffer << 8) | byte) & 0xffff;
    bits += 8;
    while (bits >= 6) {
      bits -= 6;
      text += ALPHABET[(buffer >>> bits) & 63];
    }
  }
  return bits > 0 ? text + ALPHABET[(buffer << (6 - bits)) & 63] : text;
}

/** The standard base64 alphabet, digit for digit against bcrypt's. */
const STANDARD = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/**
 * Decodes bcrypt's base64, refusing set spare bits, which `htpasswd` never matches.
 *
 * @param text - Salt or digest digits from a `$2b$` string.
 * @returns {Uint8Array} The bytes.
 */
export function bcryptBase64(text: string): Uint8Array {
  const standard = Array.from(text, (digit) => STANDARD[ALPHABET.indexOf(digit)] ?? "!").join("");
  const bytes = Uint8Array.fromBase64(standard);
  if (base64(bytes) !== text) {
    throw new InvalidOptionError("digits", text, "set bits past the last byte");
  }
  return bytes;
}

/**
 * Writes a bcrypt result as the `$2b$` string a password database or `.htpasswd` stores.
 *
 * @param salt - The 16 bytes of salt.
 * @param cost - The cost.
 * @param digest - The 23 bytes `bcrypt` returned.
 * @returns {string} `$2b$`, the cost in two digits, then 22 digits of salt and 31 of digest.
 */
export function bcryptString(salt: Uint8Array, cost: number, digest: Uint8Array): string {
  assertBytes(salt, "salt");
  assertBytes(digest, "digest");
  assertParameters(salt, cost);
  if (digest.length !== OUTPUT_LENGTH) {
    throw new InvalidOptionError("digest", digest.length, `must be ${OUTPUT_LENGTH} bytes`);
  }
  return `$2b$${String(cost).padStart(2, "0")}$${base64(salt)}${base64(digest)}`;
}
