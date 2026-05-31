/** If first arg is not a known subcommand, prepend 'hash' as default. */
export function normalizeMainArgs(argv: string[]): string[] {
  const subcommands = ['hash', 'hmac', 'algorithms', 'info', 'verify']
  if (argv.length === 0) return ['algorithms']
  const first = argv[0]!.toLowerCase()
  if (subcommands.includes(first)) return argv
  // If it looks like an algorithm name, prepend hash
  return ['hash', ...argv]
}
