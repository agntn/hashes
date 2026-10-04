/** Subcommands the CLI dispatches; any other first word is an algorithm name for `hash`. */
export const SUBCOMMANDS = [
  "hash",
  "hmac",
  "verify",
  "extend",
  "identify",
  "search",
  "algorithms",
  "info",
  "mcp",
] as const;

/**
 * Makes `hash` the default subcommand: `hashes sha256 hello` runs `hashes hash sha256 hello`.
 * No arguments lists the algorithms; a leading flag such as `--help` or `--version` goes to the
 * main command untouched.
 *
 * @param argv - Arguments after the executable and script.
 * @returns {string[]} Arguments for citty.
 */
export function normalizeMainArgs(argv: readonly string[]): string[] {
  const [first] = argv;
  if (first === undefined) return ["algorithms"];
  if (first.startsWith("-") || (SUBCOMMANDS as readonly string[]).includes(first.toLowerCase())) {
    return [...argv];
  }
  return ["hash", ...argv];
}
