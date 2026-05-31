import type { AgentToolResult, ExtensionAPI } from '@earendil-works/pi-coding-agent'
import { Text } from '@earendil-works/pi-tui'
import { Type } from 'typebox'

/** Lazy-load the library (registers all algorithms on import). */
async function loadLib() {
  const mod = await import('hashhouse').catch(() => {
    // @ts-expect-error — runtime fallback for dev (same package source)
    return import('../../../src/index.ts')
  })
  return mod as typeof import('hashhouse')
}

export default function hashhouseExtension(pi: ExtensionAPI) {
  pi.registerTool({
    name: 'hash_compute',
    label: 'Hash Compute',
    description: 'Compute a hash digest using any supported algorithm (sha256, blake3, md5, crc32, xxhash, etc.)',
    promptSnippet: 'Use hash_compute to hash text or verify checksums.',
    promptGuidelines: [
      'Specify the algorithm and input text.',
      'Default output is hex. Use encoding for base64/base64url/binary.',
      'Algorithms: sha256, sha384, sha512, sha3-256, sha3-512, blake2b, blake2s, blake3, ripemd160, whirlpool, md5, sha1, crc32, xxhash, fnv1a, scrypt, pbkdf2.',
    ],
    parameters: Type.Object({
      algorithm: Type.String({ description: 'Hash algorithm: sha256, blake3, md5, crc32, xxhash, sha3-256, blake2b, etc.' }),
      input: Type.String({ description: 'Text to hash' }),
      encoding: Type.Optional(Type.String({ description: 'Output encoding: hex (default), base64, base64url, binary' })),
    }),
    renderCall(args, _theme) {
      return new Text(`#️⃣ ${args.algorithm}: "${String(args.input).slice(0, 40)}"`, 0, 0)
    },
    async execute(_toolCallId, params): Promise<AgentToolResult> {
      try {
        const lib = await loadLib()
        const algo = lib.resolveAlgorithm(params.algorithm as string)
        const opts: Record<string, unknown> = {}
        if (params.encoding) opts.encoding = params.encoding
        const result = algo.hash(params.input as string, opts)
        const digest = typeof result.digest === 'string' ? result.digest : `[binary ${result.digestLength} bytes]`
        return {
          content: [{ type: 'text', text: digest }],
          details: { algorithm: result.algorithm, operation: result.operation, encoding: result.encoding, digestLength: result.digestLength },
        }
      } catch (e: unknown) {
        const msg = e instanceof Error ? e.message : String(e)
        return { content: [{ type: 'text', text: `Error: ${msg}` }] }
      }
    },
  })

  pi.registerTool({
    name: 'hash_hmac',
    label: 'Hash HMAC',
    description: 'Compute HMAC with a key using any HMAC-capable algorithm',
    promptSnippet: 'Use hash_hmac for keyed hash operations.',
    promptGuidelines: [
      'Requires algorithm, input, and key.',
      'Not all algorithms support HMAC (check hash_algorithms for hmac column).',
    ],
    parameters: Type.Object({
      algorithm: Type.String({ description: 'HMAC algorithm: sha256, sha512, blake2b, sha3-256, etc.' }),
      input: Type.String({ description: 'Text to HMAC' }),
      key: Type.String({ description: 'HMAC key' }),
      encoding: Type.Optional(Type.String({ description: 'Output encoding: hex (default), base64, base64url, binary' })),
    }),
    renderCall(args, _theme) {
      return new Text(`🔑 HMAC-${args.algorithm}: "${String(args.input).slice(0, 30)}"`, 0, 0)
    },
    async execute(_toolCallId, params): Promise<AgentToolResult> {
      try {
        const lib = await loadLib()
        const algo = lib.resolveAlgorithm(params.algorithm as string)
        const info = algo.info()
        if (!info.hmac) {
          return { content: [{ type: 'text', text: `Error: Algorithm "${params.algorithm}" does not support HMAC` }] }
        }
        const opts: Record<string, unknown> = { key: params.key }
        if (params.encoding) opts.encoding = params.encoding
        const result = algo.hash(params.input as string, opts)
        const digest = typeof result.digest === 'string' ? result.digest : `[binary ${result.digestLength} bytes]`
        return {
          content: [{ type: 'text', text: digest }],
          details: { algorithm: result.algorithm, operation: result.operation, encoding: result.encoding, digestLength: result.digestLength },
        }
      } catch (e: unknown) {
        const msg = e instanceof Error ? e.message : String(e)
        return { content: [{ type: 'text', text: `Error: ${msg}` }] }
      }
    },
  })

  pi.registerTool({
    name: 'hash_verify',
    label: 'Hash Verify',
    description: 'Verify input against an expected hash digest',
    promptSnippet: 'Use hash_verify to check if text matches an expected hash.',
    promptGuidelines: [
      'Provide algorithm, input text, and expected digest.',
      'Returns match/mismatch with both expected and actual values.',
    ],
    parameters: Type.Object({
      algorithm: Type.String({ description: 'Hash algorithm' }),
      input: Type.String({ description: 'Text to verify' }),
      expected: Type.String({ description: 'Expected hash digest' }),
      encoding: Type.Optional(Type.String({ description: 'Encoding of expected digest: hex (default), base64, base64url' })),
    }),
    renderCall(args, _theme) {
      return new Text(`✓ verify ${args.algorithm}: "${String(args.input).slice(0, 30)}"`, 0, 0)
    },
    async execute(_toolCallId, params): Promise<AgentToolResult> {
      try {
        const lib = await loadLib()
        const algo = lib.resolveAlgorithm(params.algorithm as string)
        const opts: Record<string, unknown> = {}
        if (params.encoding) opts.encoding = params.encoding
        const result = algo.hash(params.input as string, opts)
        const actual = typeof result.digest === 'string' ? result.digest.toLowerCase() : ''
        const expected = (params.expected as string).toLowerCase()
        const match = actual === expected
        return {
          content: [{ type: 'text', text: match ? `✓ MATCH: ${actual}` : `✗ MISMATCH\n  Expected: ${expected}\n  Actual:   ${actual}` }],
          details: { match, algorithm: result.algorithm, expected, actual },
        }
      } catch (e: unknown) {
        const msg = e instanceof Error ? e.message : String(e)
        return { content: [{ type: 'text', text: `Error: ${msg}` }] }
      }
    },
  })

  pi.registerTool({
    name: 'hash_algorithms',
    label: 'Hash Algorithms',
    description: 'List all available hash algorithms with metadata',
    promptSnippet: 'Use hash_algorithms to see available hashing algorithms.',
    promptGuidelines: [
      'Shows algorithm name, family, digest size, and HMAC support.',
      'Filter by family: cryptographic, legacy, non-cryptographic, password.',
    ],
    parameters: Type.Object({
      family: Type.Optional(Type.String({ description: 'Filter by family: cryptographic, legacy, non-cryptographic, password' })),
    }),
    renderCall(_args, _theme) {
      return new Text('📋 hash algorithms', 0, 0)
    },
    async execute(_toolCallId, params): Promise<AgentToolResult> {
      try {
        const lib = await loadLib()
        const names = lib.algorithms()
        const lines: string[] = []
        for (const name of names) {
          const algo = lib.create(name)
          const info = algo.info()
          if (params.family && info.family !== params.family) continue
          const digest = info.digestLength ? `${info.digestLength * 8}-bit` : 'variable'
          lines.push(`${info.name.padEnd(12)} ${info.family.padEnd(18)} ${digest.padEnd(10)} HMAC:${info.hmac ? '✓' : '✗'}  ${info.label}`)
        }
        return { content: [{ type: 'text', text: lines.length ? lines.join('\n') : 'No algorithms found' }] }
      } catch (e: unknown) {
        const msg = e instanceof Error ? e.message : String(e)
        return { content: [{ type: 'text', text: `Error: ${msg}` }] }
      }
    },
  })
}
