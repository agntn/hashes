# Design system

The shared rules (direction, color roles, type, the `console-*` grammar, hero, docs chrome, density, motion, checks) live in the one agntn design system document, kept with the agntn skills until it ships in the shared package. This file records only what hashes owns and where it departs from the shared rules. It does not repeat them.

The instruments hashes owns:

| Instrument | Where | Object |
| --- | --- | --- |
| [LandingHero.vue](app/components/content/LandingHero.vue) | landing, first screen | hero zone, circuit `hash` into the avalanche |
| [LandingAvalanche.vue](app/components/content/LandingAvalanche.vue) | under the hero | `hello world` and the same text one bit apart through one algorithm, both digests and every digest bit that moved |
| [LandingRotatingCode.vue](app/components/content/LandingRotatingCode.vue) | "Same call, every algorithm" | `create`, `hash`, base64 and `digestMatches` for the sample, as a file |
| [LandingVerify.vue](app/components/content/LandingVerify.vue) | "Verify compares bytes, not letters" | verdict console: the digest uppercased in hex and lowercased in base64 through `hash_verify` |
| [LandingRegistry.vue](app/components/content/LandingRegistry.vue) | the registry section | every algorithm as a grid of cells, one band per category, the walk's algorithm and the ones with its digest size on the nodes |
| [LandingToolCall.vue](app/components/content/LandingToolCall.vue) | "Four tools, one executor" | one `hash_compute` call, full text in the dialog |
| [LandingCustom.vue](app/components/content/LandingCustom.vue) | "Extend FixedHash, call register" | `fnv1a-32.ts`, a custom digest as a file |
| [LandingStart.vue](app/components/content/LandingStart.vue) | closing section | install, notes, first calls as a file |
| [AlgorithmFacts.vue](app/components/content/AlgorithmFacts.vue) | every algorithm page (`::algorithm-facts`) | algorithm dossier: ID bar with position, reticle, readout, sample digests, options, access |
| [AlgorithmRoster.vue](app/components/content/AlgorithmRoster.vue) | `/algorithms`, `/guide` (`::algorithm-roster`) | roster of the registry on `UTable`, sortable, one category with `category` |
| [HashesPlayground.vue](app/components/content/HashesPlayground.vue) | `/playground` under the hero zone | request and response instruments for the four tools |
| [Landing.takumi.vue](app/components/OgImage/Landing.takumi.vue), [Docs.takumi.vue](app/components/OgImage/Docs.takumi.vue) | OG images | the hero zone in 1200 by 600; a docs page as one instrument, an algorithm page with its blurb, category, size and the chains that use it |

Labels, families, categories, digest sizes, HMAC support and options come from `create(name).info()` through [algorithms.ts](app/utils/algorithms.ts); icons, blurbs and the chains that use an algorithm live there too. Every tool text comes from `src/tool-operations.ts` itself, the executors the MCP server runs, so nothing is mirrored.

## Anatomy

- **Avalanche.** Bar `Call create("<name>").hash("hello world")`, meta `<category> · 05 / 24`. The subject band's left column holds the algorithm (reticle, `Hash / <category>`, label, blurb; every sample's name block hidden in the same cell, so the band keeps one height) and under it the avalanche: rule `Avalanche [ one bit in, every bit it moved ]`, an `In` tape and a `Flip` tape with one boxed cell per byte, the flipped byte lit and its two values at the end, both digests on one line each with the changed hex digits in the accent, then one cell per digest bit, 64 to a row (32 under 640px), a moved bit open in the accent. The grid keeps room for the widest digest in the walk, so the band never jumps. Readout: digest size, bits moved in the accent, HMAC, the chains that use it (or the family), a tick per registered algorithm with the sample's family open. Side by side, the readout rows stretch to the height of the avalanche. Footer: link to the algorithm page, previous and next.
- **Verdict.** Bar `Call hash_verify("<name>", "hello world", …)`. Subject: `Verdict / <name>`, `same letters, other bytes`. Readout: one row per check, hex uppercased and base64 lowercased, each with a `match` or `mismatch` badge, the match on the accent edge, then a tick per digest byte, open where the lowercased base64 names another byte. `03 Full tool response` is the base64 `hash_verify` text.
- **Algorithm dossier.** ID bar with the name and `05 / 24`, meta `<family> · <size>`. Subject: reticle, `Hash / <category>`, label, blurb. Readout: digest size in the accent, HMAC, the security note cut to its first clause, the chains that use it or the family size; a tick per option, required open. Bands `Sample [ hash("hello world"), computed here ]` (hex and base64, a KDF with the fixed salt and small cost from `SAMPLE_OPTIONS`), `Options [ as info() declares them ]` and `Access [ library · CLI · playground ]` as leads with a `Kin` lead to the rest of the family, then `03 Full tool response` with the `hash_algorithms` text.
- **Registry.** Bar `Call algorithms()`, meta the count per category. One band per category under a rule title with its size, then a cell per algorithm (glyph, name, node): the walk's algorithm a filled node on an accent edge, the ones with the same digest size an accent outlined node, everything else quiet.
- **Roster.** Columns algorithm (glyph, label, boxed name), category (dropped when the roster shows one), digest, HMAC, options (required bright, optional with `?`), the security note behind a leader, the whole note in the tooltip.
- **Playground.** Request: the four tools as leads, fields as `USelectMenu`, `UTextarea` and `UInput` with variant `none` in the readout, the salt and parameter fields only for an algorithm that declares them, one chip per algorithm as `UButton` variant `chip`, CLI and tool JSON with copy. Response: a subject band per answer kind (digest with its length, input and what it depends on, verdict, listing rows, one algorithm's options, error), `03 Full tool response`, footer to the algorithm page and the guide.

## Motion

| Change | Motion |
| --- | --- |
| landing sample advances (4.2 s, paused on hover and focus) | ruler cursor once, scan and reticle arcs, readout rows slide in, bit cells drop in 2 ms apart, file name rolls, circuit runs once |
| playground answer changes | cursor and scan once per answer text, 250 ms after the form stops changing |
| reduced motion | no walk; manual previous and next still work |

## Differences

Departures from the shared rules, recorded for the shared package:

- The hero instrument is an avalanche, not a record dossier: the domain is bytes going into a hash, so the first screen shows what one flipped bit does to the digest. The number is honest per algorithm, CRC-32 included.
- One docs section for the algorithms, no tabs per family: the registry is a couple of dozen entries, well under the point where a section splits.
- The KDFs stay out of the landing walk and their pages hash the sample at a small cost, since the real defaults take seconds in a tab.
- `.console-wide` is a size container and the subject band stacks under 46rem of its own width, the rule the shared document states and the siblings don't implement yet.
- No network call anywhere: every instrument computes in the browser from the library, and every footer that names locality says `no network`.
- The version comes from the root `package.json`; there's no data version.
- The OG images ship local Figtree and Fira Code TTFs, the keys mechanism.
- There's no `public/image.png`, since `package.json` points Pi at no image.

## Checks

Beyond the shared checks: `/`, `/algorithms`, `/algorithms/hash160`, `/algorithms/scrypt` and `/playground` with a deep link for every tool (`?op=verify&algorithm=sha256&input=abc&expected=00`, `?op=algorithms&algorithm=xxhash`, `?op=hash&algorithm=scrypt&salt=73616c74&N=1024`) at 1440, 1024 and 390 px, and no horizontal scroll at 320 px.
