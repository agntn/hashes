import { readFileSync } from "node:fs";
import {
  InvalidOptionError,
  type HashInput,
  type HashResult,
  type OutputEncoding,
} from "../index.ts";

const ENCODINGS: readonly OutputEncoding[] = ["hex", "base64", "base64url", "binary"];

/** The `--encoding` flag every digest command takes. */
export const encodingArg = {
  type: "string",
  description: "Output encoding: hex, base64, base64url, binary",
  alias: "e",
  default: "hex",
} as const;

/** The `--salt` flag the KDF commands take. */
export const saltArg = {
  type: "string",
  description: "scrypt and pbkdf2: salt in hex (default: 32 random bytes, printed on stderr)",
} as const;

/**
 * Checks the `--encoding` flag.
 *
 * @param value - The flag as given.
 * @returns {OutputEncoding} The encoding.
 */
export function parseEncoding(value: string | undefined): OutputEncoding {
  const encoding = value ?? "hex";
  if ((ENCODINGS as readonly string[]).includes(encoding)) return encoding as OutputEncoding;
  throw new InvalidOptionError("encoding", encoding, `use one of ${ENCODINGS.join(", ")}`);
}

/**
 * Reads the input argument: `-` means the bytes on stdin, anything else is the text itself.
 *
 * @param value - The argument as given.
 * @returns {HashInput} Text, or the bytes read from stdin.
 */
export function readInput(value: string): HashInput {
  return value === "-" ? new Uint8Array(readFileSync(0)) : value;
}

/**
 * Prints a digest on stdout: text with a newline, bytes as they are. A salted digest cannot be
 * reproduced without its salt and cost, so those go to stderr and stdout stays the digest alone.
 *
 * @param result - The computed hash.
 */
export function printDigest(result: HashResult): void {
  const parameters = Object.entries(result.options).filter(
    ([name]) => name !== "encoding" && name !== "hmac",
  );
  if ("salt" in result.options) {
    process.stderr.write(
      `${parameters.map(([name, value]) => `${name} ${String(value)}`).join(", ")}\n`,
    );
  }
  if (typeof result.digest === "string") {
    process.stdout.write(`${result.digest}\n`);
  } else {
    process.stdout.write(result.digest);
  }
}
