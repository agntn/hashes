import { bcrypt, bcryptString, BCRYPT_SALT_LENGTH } from "../core/bcrypt.ts";
import { resolveSalt, type SaltOptions } from "../core/digest.ts";
import { Kdf, type Derivation } from "../core/kdf.ts";
import type { HashOptions } from "../core/types.ts";

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

export class Bcrypt extends Kdf<BcryptOptions> {
  static readonly key = "bcrypt";
  protected readonly about = {
    label: "bcrypt",
    description: "bcrypt password hash over the Blowfish key schedule, as OpenBSD's $2b$ runs it",
    family: "bcrypt",
    category: "password",
    digestLength: 23,
    securityNote:
      "A password past 72 bytes is refused, since $2b$ would ignore the rest. OWASP asks for a cost of at least 10.",
  } as const;
  protected override readonly options = [
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
  ] as const;
  protected override readonly roundsNote = "sets its cost with its own parameter";

  /**
   * Hashes a password with the cost and the salt, drawn when missing.
   *
   * @param bytes - The password's bytes.
   * @param options - Salt and cost.
   * @returns {Derivation} The digest, with the salt, cost and `$2b$` string it reports.
   */
  protected derive(bytes: Uint8Array, options?: Readonly<BcryptOptions>): Derivation {
    const cost = options?.cost ?? 12;
    const salt = saltOf(options);
    const digest = bcrypt(bytes, salt, cost);
    return {
      digest,
      reported: { cost, salt: salt.toHex(), crypt: bcryptString(salt, cost, digest) },
    };
  }
}
