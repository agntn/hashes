/**
 * Argument schemas of the hash tools, one declaration of every parameter for every surface.
 * `Type` comes from `@agntn/tools`, never a bare `typebox` import, which OMP rewrites to its own
 * facade (#58).
 */

import { Type, type TObject, type TProperties } from "@agntn/tools";
import {
  DIGEST_PATTERN,
  HASH_CATEGORIES,
  INPUT_ENCODINGS,
  MAX_ALGORITHM_LENGTH,
  MAX_BATCH_DIGESTS,
  MAX_BATCH_INPUTS,
  MAX_EXPECTED_LENGTH,
  MAX_FAMILY_LENGTH,
  MAX_INPUT_LENGTH,
  MAX_KEY_LENGTH,
  MAX_PARAMETER_LENGTH,
  MAX_PARAMETERS,
  MAX_JOINER_LENGTH,
  MAX_SEARCH_ALGORITHMS,
  MAX_SEARCH_JOINERS,
  MAX_SEARCH_ROUNDS,
  MAX_SEARCH_WORDS,
  MAX_SECRET_LENGTH,
  MAX_WORD_LENGTH,
  PARAMETER_NAME_PATTERN,
  PARAMETER_DESCRIPTIONS,
  SALT_PATTERN,
  SEARCH_CASES,
  SEARCH_CHAINS,
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
const oneInput = Type.String({ maxLength: MAX_INPUT_LENGTH });
const input = Type.Union(
  [oneInput, Type.Array(oneInput, { minItems: 1, maxItems: MAX_BATCH_INPUTS })],
  { description: d.input },
);
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

const secretLength = { minimum: 0, maximum: MAX_SECRET_LENGTH } as const;

export const hashDigestExtendSchema = closed({
  algorithm: Type.String({
    minLength: 1,
    maxLength: MAX_ALGORITHM_LENGTH,
    description: d.extendAlgorithm,
  }),
  digest: Type.String({ pattern: DIGEST_PATTERN, description: d.knownDigest }),
  message: Type.String({ maxLength: MAX_INPUT_LENGTH, description: d.message }),
  messageEncoding: Type.Optional(Type.Enum(INPUT_ENCODINGS, { description: d.messageEncoding })),
  suffix: Type.String({ maxLength: MAX_INPUT_LENGTH, description: d.suffix }),
  suffixEncoding: Type.Optional(Type.Enum(INPUT_ENCODINGS, { description: d.suffixEncoding })),
  secretLength: Type.Integer({ ...secretLength, description: d.secretLength }),
  secretLengthMax: Type.Optional(Type.Integer({ ...secretLength, description: d.secretLengthMax })),
});

const unknownDigest = Type.String({ minLength: 1, maxLength: MAX_EXPECTED_LENGTH });

export const hashDigestIdentifySchema = closed({
  digest: Type.Union(
    [unknownDigest, Type.Array(unknownDigest, { minItems: 1, maxItems: MAX_BATCH_DIGESTS })],
    { description: d.unknownDigest },
  ),
});

const wordCount = { minimum: 1, maximum: MAX_SEARCH_WORDS } as const;

const targetDigest = Type.String({ minLength: 1, maxLength: MAX_EXPECTED_LENGTH });

export const hashDigestSearchSchema = closed({
  digest: Type.Union(
    [targetDigest, Type.Array(targetDigest, { minItems: 1, maxItems: MAX_BATCH_DIGESTS })],
    { description: d.targetDigest },
  ),
  encoding: Type.Optional(Type.Enum(TEXT_ENCODINGS, { description: d.targetEncoding })),
  words: Type.Array(Type.String({ minLength: 1, maxLength: MAX_WORD_LENGTH }), {
    minItems: 1,
    maxItems: MAX_SEARCH_WORDS,
    description: d.words,
  }),
  minWords: Type.Optional(Type.Integer({ ...wordCount, description: d.minWords })),
  maxWords: Type.Optional(Type.Integer({ ...wordCount, description: d.maxWords })),
  joiners: Type.Optional(
    Type.Array(Type.String({ maxLength: MAX_JOINER_LENGTH }), {
      minItems: 1,
      maxItems: MAX_SEARCH_JOINERS,
      description: d.joiners,
    }),
  ),
  cases: Type.Optional(
    Type.Array(Type.Enum(SEARCH_CASES), {
      minItems: 1,
      maxItems: SEARCH_CASES.length,
      description: d.cases,
    }),
  ),
  algorithms: Type.Optional(
    Type.Array(Type.String({ minLength: 1, maxLength: MAX_ALGORITHM_LENGTH }), {
      minItems: 1,
      maxItems: MAX_SEARCH_ALGORITHMS,
      description: d.searchAlgorithms,
    }),
  ),
  rounds: Type.Optional(
    Type.Integer({ minimum: 1, maximum: MAX_SEARCH_ROUNDS, description: d.rounds }),
  ),
  chains: Type.Optional(
    Type.Array(Type.Enum(SEARCH_CHAINS), {
      minItems: 1,
      maxItems: SEARCH_CHAINS.length,
      description: d.chains,
    }),
  ),
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

/** The tool schemas, keyed by tool name, in listing order. */
export const toolSchemas = {
  hashes_compute: hashComputeSchema,
  hashes_hmac_compute: hashHmacSchema,
  hashes_verify: hashVerifySchema,
  hashes_digest_extend: hashDigestExtendSchema,
  hashes_digest_identify: hashDigestIdentifySchema,
  hashes_digest_search: hashDigestSearchSchema,
  hashes_algorithms: hashAlgorithmsSchema,
};
