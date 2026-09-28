import { defineCommand } from "citty";
import { digestMatches, resolveAlgorithm } from "../index.ts";
import { parseEncoding, readInput, saltArg } from "./shared.ts";

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
    salt: saltArg,
  },
  run({ args }) {
    const algorithm = resolveAlgorithm(args.algorithm);
    const encoding = parseEncoding(args.encoding);
    const salt = args.salt === undefined ? {} : { salt: args.salt };
    const result = algorithm.hash(readInput(args.input), { encoding, ...salt });
    if (digestMatches(result, args.expected)) {
      process.stdout.write(`MATCH ${algorithm.name()} ${String(result.digest)}\n`);
      return;
    }
    process.stdout.write(
      `MISMATCH ${algorithm.name()}\n  expected ${args.expected.trim()}\n  actual   ${String(result.digest)}\n`,
    );
    process.exitCode = 1;
  },
});
