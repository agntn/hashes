import { defineCommand } from "citty";
import { resolveAlgorithm } from "../index.ts";
import { encodingArg, parseEncoding, printDigest, readInput, saltArg } from "./shared.ts";

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
    salt: saltArg,
  },
  run({ args }) {
    const algorithm = resolveAlgorithm(args.algorithm);
    const encoding = parseEncoding(args.encoding);
    const salt = args.salt === undefined ? {} : { salt: args.salt };
    printDigest(algorithm.hash(readInput(args.input), { encoding, ...salt }));
  },
});
