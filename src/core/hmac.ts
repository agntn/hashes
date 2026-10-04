/** HMAC (RFC 2104) over any `Hasher`, and PBKDF2 (RFC 8018) and HKDF (RFC 5869) over HMAC. */
import { InvalidOptionError } from "./errors.ts";
import { type Hasher, assertBytes, createHasher } from "./hasher.ts";

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
  const inner = createHasher(create);
  const block = new Uint8Array(inner.blockLength);
  block.set(key.length > block.length ? createHasher(create).update(key).digest() : key);
  for (let i = 0; i < block.length; i++) block[i] = block[i]! ^ 0x36;
  inner.update(block);
  for (let i = 0; i < block.length; i++) block[i] = block[i]! ^ (0x36 ^ 0x5c);
  const outer = createHasher(create).update(block);
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
  assertBytes(key, "key");
  assertBytes(message, "message");
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
  assertBytes(password, "password");
  assertBytes(salt, "salt");
  for (const [name, value] of [
    ["iterations", iterations],
    ["keyLength", keyLength],
  ] as const) {
    if (!Number.isSafeInteger(value) || value < 1) {
      throw new InvalidOptionError(name, value, "must be a positive integer");
    }
  }
  const keyed = keyHmac(create, password);
  const inner = createHasher(create);
  const outer = createHasher(create);
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

/**
 * Runs HKDF's extract step. An empty salt equals the RFC's zero salt, as HMAC pads the key.
 *
 * @param create - Creates a fresh hasher of the underlying hash.
 * @param salt - The salt, empty for none.
 * @param ikm - The input key material.
 * @returns {Uint8Array} The pseudorandom key, as long as the hash's digest.
 */
export function hkdfExtract(create: () => Hasher, salt: Uint8Array, ikm: Uint8Array): Uint8Array {
  assertBytes(salt, "salt");
  assertBytes(ikm, "ikm");
  return hmac(create, salt, ikm);
}

/**
 * Runs the expand step of HKDF, which chains HMAC blocks keyed with the pseudorandom key.
 *
 * @param create - Creates a fresh hasher of the underlying hash.
 * @param prk - The pseudorandom key, usually from `hkdfExtract`.
 * @param info - Context that binds the output to its use, empty for none.
 * @param length - Output bytes, at most 255 digests.
 * @returns {Uint8Array} The output key material.
 */
export function hkdfExpand(
  create: () => Hasher,
  prk: Uint8Array,
  info: Uint8Array,
  length: number,
): Uint8Array {
  assertBytes(prk, "prk");
  assertBytes(info, "info");
  const keyed = keyHmac(create, prk);
  const hashLength = keyed.inner.outputLength;
  if (!Number.isSafeInteger(length) || length < 1 || length > 255 * hashLength) {
    throw new InvalidOptionError("keyLength", length, `must be 1 to ${255 * hashLength} bytes`);
  }
  const inner = createHasher(create);
  const outer = createHasher(create);
  const block = new Uint8Array(hashLength);
  const counter = new Uint8Array(1);
  const out = new Uint8Array(length);
  for (let index = 1, offset = 0; offset < length; offset += hashLength, index++) {
    counter[0] = index;
    inner.load(keyed.inner);
    if (index > 1) inner.update(block);
    inner.update(info).update(counter).digestInto(block);
    outer.load(keyed.outer).update(block).digestInto(block);
    out.set(block.subarray(0, Math.min(hashLength, length - offset)), offset);
  }
  return out;
}

/**
 * Derives a key with HKDF: extract, then expand.
 *
 * @param create - Creates a fresh hasher of the underlying hash.
 * @param ikm - The input key material, such as a shared secret.
 * @param salt - The salt, empty for none.
 * @param info - Context that binds the output to its use, empty for none.
 * @param length - Output bytes, at most 255 digests.
 * @returns {Uint8Array} The derived key.
 */
export function hkdf(
  create: () => Hasher,
  ikm: Uint8Array,
  salt: Uint8Array,
  info: Uint8Array,
  length: number,
): Uint8Array {
  return hkdfExpand(create, hkdfExtract(create, salt, ikm), info, length);
}
