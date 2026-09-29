/** HMAC (RFC 2104) over any `Hasher`, and PBKDF2 (RFC 8018) over HMAC. */
import type { Hasher } from "./hasher.ts";

/** A hash keyed for HMAC: the inner and outer states after their one padded key block each. */
interface KeyedHmac {
  inner: Hasher;
  outer: Hasher;
}

/**
 * Absorbs the padded key into an inner and an outer hasher. A key longer than the block is hashed
 * first, as the RFC asks.
 *
 * @param create - Creates a fresh hasher of the underlying hash.
 * @param key - The HMAC key.
 * @returns {KeyedHmac} The two keyed states.
 */
function keyHmac(create: () => Hasher, key: Uint8Array): KeyedHmac {
  const inner = create();
  const block = new Uint8Array(inner.blockLength);
  block.set(key.length > block.length ? create().update(key).digest() : key);
  for (let i = 0; i < block.length; i++) block[i] = block[i]! ^ 0x36;
  inner.update(block);
  for (let i = 0; i < block.length; i++) block[i] = block[i]! ^ (0x36 ^ 0x5c);
  const outer = create().update(block);
  return { inner, outer };
}

/**
 * Computes an HMAC.
 *
 * @param create - Creates a fresh hasher of the underlying hash.
 * @param key - The HMAC key.
 * @param message - The message.
 * @returns {Uint8Array} The tag, as long as the hash's digest.
 */
export function hmac(create: () => Hasher, key: Uint8Array, message: Uint8Array): Uint8Array {
  const { inner, outer } = keyHmac(create, key);
  return outer.update(inner.update(message).digest()).digest();
}

/**
 * Derives a key with PBKDF2-HMAC. The keyed states are built once and copied into two working
 * hashers on every iteration, so an iteration costs the blocks of the running value alone.
 *
 * @param create - Creates a fresh hasher of the underlying hash.
 * @param password - The password.
 * @param salt - The salt.
 * @param iterations - Iteration count, at least 1.
 * @param keyLength - Output bytes.
 * @returns {Uint8Array} The derived key.
 */
export function pbkdf2(
  create: () => Hasher,
  password: Uint8Array,
  salt: Uint8Array,
  iterations: number,
  keyLength: number,
): Uint8Array {
  const keyed = keyHmac(create, password);
  const inner = create();
  const outer = create();
  const length = inner.outputLength;
  const u = new Uint8Array(length);
  const t = new Uint8Array(length);
  const first = new Uint8Array(salt.length + 4);
  first.set(salt);
  const counter = new DataView(first.buffer, salt.length);
  const out = new Uint8Array(keyLength);
  for (let index = 1, offset = 0; offset < keyLength; offset += length, index++) {
    counter.setUint32(0, index);
    inner.load(keyed.inner).update(first).digestInto(u);
    outer.load(keyed.outer).update(u).digestInto(u);
    t.set(u);
    for (let i = 1; i < iterations; i++) {
      inner.load(keyed.inner).update(u).digestInto(u);
      outer.load(keyed.outer).update(u).digestInto(u);
      for (let j = 0; j < length; j++) t[j] = t[j]! ^ u[j]!;
    }
    out.set(t.subarray(0, Math.min(length, keyLength - offset)), offset);
  }
  return out;
}
