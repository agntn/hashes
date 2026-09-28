import { defineCommand } from "citty";
import { resolveAlgorithm, type HashOptions } from "../index.ts";
import {
  encodingArg,
  parameterArgs,
  parseEncoding,
  printDigest,
  readInput,
  readParameters,
} from "./shared.ts";

export default defineCommand({
  meta: { name: "hash", description: "Hash input with an algorithm" },
  args: {
    algorithm: {
      type: "positional",
      description: "Algorithm name (sha256, blake3, md5, ...)",
      required: true,
    },
    input: { type: "positional", description: "Text to hash, or - for stdin", required: true },
    encoding: encodingArg,
    ...parameterArgs,
  },
  run({ args }) {
    const algorithm = resolveAlgorithm(args.algorithm);
    const encoding = parseEncoding(args.encoding);
    const parameters = readParameters(algorithm, args);
    printDigest(algorithm.hash(readInput(args.input), { encoding, ...parameters } as HashOptions));
  },
});
