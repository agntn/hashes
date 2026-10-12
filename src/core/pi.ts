/**
 * π by Machin's formula, π = 16·arctan(1/5) - 4·arctan(1/239), in BigInt. MD2's table, Blowfish's
 * state and HAVAL's constants all come out of its digits, so none of them ships a table.
 */

/**
 * Sums the series of arctan(1/x), scaled by `one`.
 *
 * @param x - The inverse of the argument.
 * @param one - The scale.
 * @returns {bigint} About arctan(1/x) times `one`.
 */
function arctanInverse(x: bigint, one: bigint): bigint {
  let power = one / x;
  let sum = power;
  for (let n = 3n, sign = -1n; power !== 0n; n += 2n, sign = -sign) {
    power /= x * x;
    sum += (sign * power) / n;
  }
  return sum;
}

/**
 * Computes π scaled by `one`. Each term is truncated, so the last few digits are off: ask for
 * guard digits and drop them.
 *
 * @param one - The scale: `10n ** digits` for decimal digits, `1n << bits` for binary ones.
 * @returns {bigint} About π times `one`.
 */
export function machinPi(one: bigint): bigint {
  return 16n * arctanInverse(5n, one) - 4n * arctanInverse(239n, one);
}

/**
 * Reads the hexadecimal digits of π after the point as 32-bit words.
 *
 * @param count - Words to compute.
 * @returns {Uint32Array} `count` words, `0x243f6a88` first.
 */
export function piWords(count: number): Uint32Array {
  const bits = BigInt(32 * count + 64);
  const fraction = (machinPi(1n << bits) - (3n << bits)) >> 64n;
  const hex = fraction.toString(16).padStart(8 * count, "0");
  const words = new Uint32Array(count);
  for (let i = 0; i < count; i++) words[i] = Number.parseInt(hex.slice(8 * i, 8 * i + 8), 16);
  return words;
}
