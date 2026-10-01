import { defineCommand } from "citty";
import { shown } from "../core/errors.ts";
import { assertDrawnOptions, assertExpected } from "../core/verify.ts";
import { digestMatches, resolveAlgorithm, type HashOptions } from "../index.ts";
import {
  inputEncodingArg,
  parameterArgs,
  parseEncoding,
  readInput,
  readParameters,
} from "./shared.ts";

export default defineCommand({
  meta: { name: "verify", description: "Verify input against an expected hash" },
  args: {
    algorithm: { type: "positional", description: "Algorithm name", required: true },
    input: { type: "positional", description: "Text to hash, or - for stdin", required: true },
    expected: { type: "positional", description: "Expected hash digest", required: true },
    encoding: {
      type: "string",
      description: "Encoding of the expected digest: hex, base64, base64url",
      alias: "e",
      default: "hex",
    },
    "input-encoding": inputEncodingArg,
    ...parameterArgs,
  },
  run({ args }) {
    const algorithm = resolveAlgorithm(args.algorithm);
    const encoding = parseEncoding(args.encoding);
    assertExpected(args.expected, encoding);
    const parameters = readParameters(algorithm, args);
    assertDrawnOptions(algorithm.info(), parameters);
    const result = algorithm.hash(readInput(args.input, args["input-encoding"]), {
      encoding,
      ...parameters,
    } as HashOptions);
    if (digestMatches(result, args.expected)) {
      process.stdout.write(`MATCH ${algorithm.name()} ${String(result.digest)}\n`);
      return;
    }
    process.stdout.write(
      `MISMATCH ${algorithm.name()}\n  expected ${shown(args.expected.trim())}\n  actual   ${String(result.digest)}\n`,
    );
    process.exitCode = 1;
  },
});
