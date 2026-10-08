import { bcrypt, bcryptString, BCRYPT_SALT_LENGTH } from "../core/bcrypt.ts";
import {
  isInputList,
  assertOneRound,
  ENCODING_OPTION,
  encodeDigest,
  guarded,
  resolveSalt,
  toBytes,
  type SaltOptions,
} from "../core/digest.ts";
import { Hash } from "../core/hash.ts";
import type { AlgorithmInfo, HashInput, HashOptions, HashResult } from "../core/types.ts";

/** Options bcrypt takes besides the encoding. */
export interface BcryptOptions extends HashOptions, SaltOptions {
  /** Base-2 logarithm of the rounds, 4 to 31. Default: 12. */
  cost?: number;
}

/**
 * Reads the salt, or draws the 16 bytes bcrypt takes.
 *
 * @param options - The bcrypt options.
 * @returns {Uint8Array} The salt.
 */
function saltOf(options?: Readonly<BcryptOptions>): Uint8Array {
  if (options?.salt === undefined) {
    return crypto.getRandomValues(new Uint8Array(BCRYPT_SALT_LENGTH));
  }
  return resolveSalt(options);
}

export class Bcrypt extends Hash {
  static readonly key = "bcrypt";

  /**
   * Describes the algorithm.
   *
   * @returns {AlgorithmInfo} Its metadata.
   */
  info(): AlgorithmInfo {
    return {
      name: this.key,
      label: "bcrypt",
      description: "bcrypt password hash over the Blowfish key schedule, as OpenBSD's $2b$ runs it",
      family: "bcrypt",
      category: "password",
      digestLength: 23,
      hmac: false,
      options: [
        ENCODING_OPTION,
        {
          name: "salt",
          type: "string",
          required: false,
          random: true,
          description: `Salt in hex, ${BCRYPT_SALT_LENGTH} bytes; ${BCRYPT_SALT_LENGTH} random bytes when omitted`,
        },
        {
          name: "cost",
          type: "number",
          required: false,
          default: 12,
          description: "Base-2 logarithm of the rounds, 4 to 31",
        },
      ],
      securityNote:
        "A password past 72 bytes is refused, since $2b$ would ignore the rest. OWASP asks for a cost of at least 10.",
    };
  }

  /**
   * Hashes a password.
   *
   * @param input - Text or bytes, or a list of them.
   * @param options - Encoding, salt and cost.
   * @returns {HashResult | HashResult[]} The digest with its `$2b$` string, one per input.
   */
  hash(input: HashInput, options?: Readonly<BcryptOptions>): HashResult;
  hash(inputs: readonly HashInput[], options?: Readonly<BcryptOptions>): HashResult[];
  hash(
    input: HashInput | readonly HashInput[],
    options?: Readonly<BcryptOptions>,
  ): HashResult | HashResult[] {
    if (isInputList(input)) return input.map((one) => this.hash(one, options));
    return guarded(this.key, () => {
      if (options?.key !== undefined) throw new Error(`${this.key} has no HMAC mode`);
      assertOneRound(options, `${this.key} sets its cost with its own parameter`);
      const cost = options?.cost ?? 12;
      const salt = saltOf(options);
      const raw = bcrypt(toBytes(input), salt, cost);
      return encodeDigest(raw, this.key, "hash", options?.encoding ?? "hex", {
        cost,
        salt: salt.toHex(),
        crypt: bcryptString(salt, cost, raw),
      });
    });
  }
}
