/**
 * TypeBox schemas of the hash tools, shared by the MCP server and the Pi extension so every
 * parameter has one declaration. OMP validates with its own TypeBox build and restates them; a
 * test holds its copy to the same contract.
 */

import { Type, type TObject, type TProperties } from "typebox";
import {
  HASH_CATEGORIES,
  INPUT_ENCODINGS,
  MAX_ALGORITHM_LENGTH,
  MAX_EXPECTED_LENGTH,
  MAX_FAMILY_LENGTH,
  MAX_INPUT_LENGTH,
  MAX_KEY_LENGTH,
  MAX_PARAMETER_LENGTH,
  MAX_PARAMETERS,
  PARAMETER_NAME_PATTERN,
  PARAMETER_DESCRIPTIONS,
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

const d = PARAMETER_DESCRIPTIONS;
const algorithm = Type.String({
  minLength: 1,
  maxLength: MAX_ALGORITHM_LENGTH,
  description: d.algorithm,
});
const input = Type.String({ maxLength: MAX_INPUT_LENGTH, description: d.input });
const inputEncoding = Type.Optional(Type.Enum(INPUT_ENCODINGS, { description: d.inputEncoding }));
const encoding = Type.Optional(Type.Enum(TEXT_ENCODINGS, { description: d.encoding }));
const salt = Type.Optional(Type.String({ pattern: SALT_PATTERN, description: d.salt }));
const parameters = Type.Optional(
  Type.Record(
    Type.String({ pattern: PARAMETER_NAME_PATTERN }),
    Type.Union([Type.Integer(), Type.String({ maxLength: MAX_PARAMETER_LENGTH })]),
    { maxProperties: MAX_PARAMETERS, additionalProperties: false, description: d.parameters },
  ),
);

export const hashComputeSchema = closed({
  algorithm,
  input,
  inputEncoding,
  encoding,
  salt,
  parameters,
});

export const hashHmacSchema = closed({
  algorithm: Type.String({
    minLength: 1,
    maxLength: MAX_ALGORITHM_LENGTH,
    description: d.hmacAlgorithm,
  }),
  input,
  inputEncoding,
  key: Type.String({ maxLength: MAX_KEY_LENGTH, description: d.key }),
  keyEncoding: Type.Optional(Type.Enum(INPUT_ENCODINGS, { description: d.keyEncoding })),
  encoding,
});

export const hashVerifySchema = closed({
  algorithm,
  input,
  inputEncoding,
  expected: Type.String({
    minLength: 1,
    maxLength: MAX_EXPECTED_LENGTH,
    description: d.expected,
  }),
  encoding: Type.Optional(Type.Enum(TEXT_ENCODINGS, { description: d.expectedEncoding })),
  salt: Type.Optional(Type.String({ pattern: SALT_PATTERN, description: d.verifySalt })),
  parameters,
});

export const hashAlgorithmsSchema = closed({
  category: Type.Optional(Type.Enum(HASH_CATEGORIES, { description: d.category })),
  family: Type.Optional(
    Type.String({ minLength: 1, maxLength: MAX_FAMILY_LENGTH, description: d.family }),
  ),
  algorithm: Type.Optional(
    Type.String({ minLength: 1, maxLength: MAX_ALGORITHM_LENGTH, description: d.describe }),
  ),
});

/** The four tool schemas, keyed by tool name, in listing order. */
export const toolSchemas = {
  hashes_compute: hashComputeSchema,
  hashes_hmac_compute: hashHmacSchema,
  hashes_verify: hashVerifySchema,
  hashes_algorithms: hashAlgorithmsSchema,
};
