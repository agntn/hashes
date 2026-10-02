import { defineCommand } from "citty";
import { MAX_SECRET_LENGTHS } from "../../packages/shared/tool-contract.ts";
import { decodeInput, toBytes } from "../core/digest.ts";
import { extendDigest, secretLengths } from "../core/extend.ts";
import { InvalidOptionError, MissingOptionError } from "../index.ts";
import { parseInputEncoding } from "./shared.ts";

/**
 * Reads a secret length flag as a whole number of bytes.
 *
 * @param flag - The flag name, for the error.
 * @param value - The flag as given.
 * @returns {number} The length.
 */
function readLength(flag: string, value: string): number {
  if (!/^\d{1,15}$/.test(value)) {
    throw new InvalidOptionError(flag, value, "must be a whole number of bytes");
  }
  return Number(value);
}

export default defineCommand({
  meta: {
    name: "extend",
    description:
      "Length extension: from H(secret || message) and the secret's length, the digest of secret || message || padding || suffix",
  },
  args: {
    algorithm: {
      type: "positional",
      description: "Merkle-Damgard algorithm (sha256, sha512, sha1, md5, ripemd160, ...)",
      required: true,
    },
    digest: {
      type: "positional",
      description: "Known digest of the secret followed by the message, in hex",
      required: true,
    },
    message: { type: "string", description: "The message after the secret (default empty)" },
    suffix: { type: "string", description: "What to append after the padding" },
    "secret-length": { type: "string", description: "Length of the secret in bytes" },
    "secret-length-max": {
      type: "string",
      description: `Try every secret length up to this one, at most ${MAX_SECRET_LENGTHS}`,
    },
    "message-encoding": {
      type: "string",
      description: "How to read the message: utf8, hex or base64",
      default: "utf8",
    },
    "suffix-encoding": {
      type: "string",
      description: "How to read the suffix: utf8, hex or base64",
      default: "utf8",
    },
  },
  run({ args }) {
    if (args.suffix === undefined) throw new MissingOptionError("suffix");
    const first = args["secret-length"];
    if (first === undefined) throw new MissingOptionError("secret-length");
    const last = args["secret-length-max"];
    const lengths = secretLengths(
      readLength("secret-length", first),
      last === undefined ? undefined : readLength("secret-length-max", last),
      MAX_SECRET_LENGTHS,
    );
    const digest = toBytes(decodeInput(args.digest, "hex", "digest"));
    const message = toBytes(
      decodeInput(
        args.message ?? "",
        parseInputEncoding("message-encoding", args["message-encoding"]),
        "message",
      ),
    );
    const suffix = toBytes(
      decodeInput(
        args.suffix,
        parseInputEncoding("suffix-encoding", args["suffix-encoding"]),
        "suffix",
      ),
    );
    for (const secretLength of lengths) {
      const forged = extendDigest({
        algorithm: args.algorithm,
        digest,
        message,
        secretLength,
        suffix,
      });
      process.stdout.write(`${secretLength} ${forged.digest.toHex()} ${forged.message.toHex()}\n`);
    }
  },
});
