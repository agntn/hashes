/** OpenSSL's EVP_BytesToKey, behind `openssl enc` without `-pbkdf2` and CryptoJS's EvpKDF. */
import { InvalidOptionError } from "./errors.ts";
import { type Hasher, assertBytes } from "./hasher.ts";

/**
 * Derives bytes the way OpenSSL's EVP_BytesToKey does: each block hashes the one before it, the
 * password and the salt, then hashes itself again until it has had `iterations` passes.
 *
 * @param create - Creates a fresh hasher of the digest, `Md5Hasher` for `openssl enc` before 1.1.0.
 * @param password - The password.
 * @param salt - The salt, 8 bytes in OpenSSL, empty for none.
 * @param iterations - Hash passes per block, at least 1.
 * @param length - Bytes to derive, the key and then the IV.
 * @returns {Uint8Array} The derived bytes.
 */
export function evpBytesToKey(
  create: () => Hasher,
  password: Uint8Array,
  salt: Uint8Array,
  iterations: number,
  length: number,
): Uint8Array {
  assertBytes(password, "password");
  assertBytes(salt, "salt");
  for (const [name, value] of [
    ["iterations", iterations],
    ["length", length],
  ] as const) {
    if (!Number.isSafeInteger(value) || value < 1) {
      throw new InvalidOptionError(name, value, "must be a positive integer");
    }
  }
  const fresh = create();
  const hasher = create();
  const block = new Uint8Array(hasher.outputLength);
  const out = new Uint8Array(length);
  for (let offset = 0; offset < length; offset += block.length) {
    hasher.load(fresh);
    if (offset > 0) hasher.update(block);
    hasher.update(password).update(salt).digestInto(block);
    for (let i = 1; i < iterations; i++) hasher.load(fresh).update(block).digestInto(block);
    out.set(block.subarray(0, Math.min(block.length, length - offset)), offset);
  }
  return out;
}
