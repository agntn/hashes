/**
 * TypeBox schemas of the hash tools, shared by the MCP server and the Pi extension so every
 * parameter has one declaration. OMP validates with its own TypeBox build and restates them; a
 * test holds its copy to the same contract.
 */

import { Type, type TObject, type TProperties } from "typebox";
import {
  BUILTIN_ALGORITHMS,
  HASH_FAMILIES,
  HMAC_ALGORITHMS,
  MAX_ALGORITHM_LENGTH,
  MAX_EXPECTED_LENGTH,
  MAX_INPUT_LENGTH,
  MAX_KEY_LENGTH,
  SALT_PATTERN,
  TEXT_ENCODINGS,
} from "./tool-contract.ts";

/**
 * An object schema that rejects keys it does not declare, so a misspelled optional argument
 * fails instead of being dropped.
 *
 * @param properties - The declared properties.
 * @returns {TObject} The closed object schema.
 */
function closed<T extends TProperties>(properties: T): TObject<T> {
  return Type.Object(properties, { additionalProperties: false });
}

const algorithm = Type.String({
  minLength: 1,
  maxLength: MAX_ALGORITHM_LENGTH,
  description: `Algorithm name, case-insensitive: ${BUILTIN_ALGORITHMS}`,
});
const input = Type.String({
  maxLength: MAX_INPUT_LENGTH,
  description: "Text to hash, read as UTF-8",
});
const encoding = Type.Optional(
  Type.Enum(TEXT_ENCODINGS, { description: "Digest encoding (default hex)" }),
);
const salt = Type.Optional(
  Type.String({
    pattern: SALT_PATTERN,
    description:
      "scrypt and pbkdf2 only: salt in hex. Omitted, a random 32-byte salt is drawn and the answer names it; hash_verify needs it",
  }),
);

export const hashComputeSchema = closed({ algorithm, input, encoding, salt });

export const hashHmacSchema = closed({
  algorithm: Type.String({
    minLength: 1,
    maxLength: MAX_ALGORITHM_LENGTH,
    description: `Algorithm with an HMAC mode: ${HMAC_ALGORITHMS}`,
  }),
  input,
  key: Type.String({ maxLength: MAX_KEY_LENGTH, description: "HMAC key, read as UTF-8" }),
  encoding,
});

export const hashVerifySchema = closed({
  algorithm,
  input,
  expected: Type.String({
    minLength: 1,
    maxLength: MAX_EXPECTED_LENGTH,
    description: "Expected digest. Hex ignores case; base64 and base64url do not",
  }),
  encoding: Type.Optional(
    Type.Enum(TEXT_ENCODINGS, { description: "Encoding of the expected digest (default hex)" }),
  ),
  salt: Type.Optional(
    Type.String({
      pattern: SALT_PATTERN,
      description:
        "scrypt and pbkdf2 only, and required there: the salt in hex the expected digest was made with",
    }),
  ),
});

export const hashAlgorithmsSchema = closed({
  family: Type.Optional(
    Type.Enum(HASH_FAMILIES, { description: "Family to list; omit to list every family" }),
  ),
  algorithm: Type.Optional(
    Type.String({
      minLength: 1,
      maxLength: MAX_ALGORITHM_LENGTH,
      description: "Registered algorithm to describe with its options; omit to list",
    }),
  ),
});
