import { defineCommand } from "citty";
import { InvalidOptionError, resolveAlgorithm } from "../index.ts";
import {
  encodingArg,
  inputEncodingArg,
  keyEncodingArg,
  parseEncoding,
  printDigest,
  readInput,
  readKey,
} from "./shared.ts";

export default defineCommand({
  meta: { name: "hmac", description: "Compute HMAC with an algorithm" },
  args: {
    algorithm: {
      type: "positional",
      description: "Algorithm name (sha256, sha512, blake2b, ...)",
      required: true,
    },
    input: { type: "positional", description: "Text to HMAC, or - for stdin", required: true },
    key: { type: "positional", description: "HMAC key", required: true },
    "input-encoding": inputEncodingArg,
    "key-encoding": keyEncodingArg,
    encoding: encodingArg,
  },
  run({ args }) {
    const algorithm = resolveAlgorithm(args.algorithm);
    if (!algorithm.info().hmac) {
      throw new InvalidOptionError("algorithm", algorithm.name(), "has no HMAC mode");
    }
    const encoding = parseEncoding(args.encoding);
    const key = readKey(args.key, args["key-encoding"]);
    printDigest(algorithm.hash(readInput(args.input, args["input-encoding"]), { encoding, key }));
  },
});
