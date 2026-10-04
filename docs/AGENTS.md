# docs/

Docus site for `@agntn/hashes` at hashes.agntn.dev. Markdown lives in `content/`. The playground is a Vue page that imports the library into the browser. The one route that answers at request time is `/mcp`, the Docus MCP server with every tool of `hashes mcp` beside its own `list-pages` and `get-page`.

## Layout

```
docs/
├── DESIGN.md                      # the instruments this site owns and where it departs from the agntn design system
├── nuxt.config.ts                 # extends: ['docus'], cloudflare_module preset (Workers), @agntn/hashes, @agntn/hashes/mcp and #tool-operations aliased to ../src
├── shiki-theme.ts                 # code block theme, every colour a --shiki-token-* variable from app.css
├── app/app.config.ts              # title, github, theme, the Nuxt UI variants in the instrument grammar
├── app/app.css                    # theme tokens, the shared `console-*` and `hero-*` grammar, `hashes-*` classes
├── app/components/                # Docus overrides: header, tabs, sidebar, table of contents, page links, surround, callout; icons are Lucide and token, brands simple-icons
├── app/components/content/        # MDC components (`::landing-home`, `::algorithm-facts`, `::algorithm-roster`), the landing instruments, Prose* overrides, HashesPlayground
├── app/components/OgImage/        # Docs.takumi and Landing.takumi override the Docus OG templates
├── app/assets/fonts.css           # @font-face for the TTFs served from public/fonts (site and OG images)
├── app/composables/               # useLandingHash (one clock for every live panel), useSubNavigation, useCopied, useRosterFlip
├── app/utils/                     # algorithms table (icons, blurbs, chains over the library's info()), tools (the agent tools' text), tokens, roster, formatting
├── app/pages/playground.vue       # playground, own route outside the docs layout, its own useSeo and OG image
├── server/routes/sitemap.xml.ts   # Docus sitemap plus the Vue pages it cannot see
├── server/mcp/index.ts            # the Docus MCP handler at /mcp, named and versioned like `hashes mcp`
├── server/mcp/tools/              # one file per hash tool, each `hashesMcpTool("<name>")`
├── server/utils/hashes-mcp.ts     # a tool from `@agntn/hashes/mcp`: its entry in `toolListings` and `callTool`, the TypeBox schema read into Zod
├── public/                        # fonts, favicon.svg and the icons and manifest cut from it
├── content/index.md               # landing
├── content/1.guide/               # getting started, hashing, HMAC and verify, KDFs, length extension, identify, search, CLI, agents, custom, playground
└── content/2.algorithms/          # overview, one page per algorithm in listing order
```

## Commands

```bash
pnpm install          # from docs/, the repo root needs no install or build first
pnpm dev              # http://localhost:3000
pnpm build            # Cloudflare Workers output in .output/, content routes prerendered
pnpm deploy           # build, then wrangler deploy to hashes.agntn.dev
pnpm exec nuxt prepare --extends docus && pnpm exec vue-tsc --noEmit -p .nuxt/tsconfig.app.json   # type check, .vue files included
```

Deployment: Workers Builds with root directory `docs`. It installs `docs/` and nothing else, and that's enough, because the library comes from `../src` (next paragraph). Nitro preset `cloudflare_module`. Nuxt Content wants a D1 binding named `DB`. `wrangler.jsonc` carries it plus the `NUXT_SITE_URL` var. The database `agntn-hashes` lives in the EU jurisdiction, which is set at creation; the binding names it by id alone. No KV binding. Nothing is fetched, so nothing is cached.

`@agntn/hashes` is an alias in `nuxt.config.ts` for `../src/index.ts`, and `#tool-operations` for `../src/tool-operations.ts`. Vite bundles the checkout's sources for the browser and Nitro gets the same alias for the prerender, so `dist/` and the root `node_modules` are never touched. That works because nothing under `src/index.ts` or `src/tool-operations.ts` imports `node:*` or npm; the executors take only types from `@agntn/tools`. `src/mcp.ts` does import npm, see [MCP](#mcp). A new npm import under `src/core`, `src/algorithms` or `packages/shared` needs three entries here or it breaks the deploy: a dependency pinned to the root's version, plus `vite.resolve.dedupe` and `vite.optimizeDeps.include`, since Vite resolves a bare import in `../src` from the repo root upward, never from `docs/node_modules`.

The library needs `Uint8Array` with native hex and base64 (`toHex`, `fromHex`, `fromBase64`), in the browser as on Node 26. A browser without them can't run the playground. The TypeScript that Docus brings (5.9) has no types for them yet, so the type check under Commands reports them in `../src`. Those lines are the library's, checked by the root `tsc`; count only errors under `app/`.

Two resolution traps, both because the repo root is its own pnpm workspace:

- `pnpm-workspace.yaml` sets `shamefullyHoist: true`. Without it `docs/node_modules` holds only direct dependencies, Node walks up to the root `node_modules`, and the server bundle can end up with a second copy of Vue.
- `nuxt.config.ts` pins `workspaceDir` to `docs/`, disables devtools and telemetry, and adds `../src` to `vite.server.fs.allow`, since `pnpm dev` couldn't load the library otherwise.

## MCP

`@agntn/hashes/mcp` is a third alias, for `../src/mcp.ts`. A file in `server/mcp/tools/` names one tool and nothing else: `hashesMcpTool()` takes the name, prose and annotations from `toolListings` and runs `callTool()` from there, so a tool changed in `src/` changes here without an edit. A new tool in `src/tools.ts` needs one more file here, and `test/docs-mcp.test.ts` fails until it has one. `@nuxtjs/mcp-toolkit` wants Zod, so its schema is `z.fromJSONSchema()` over the TypeBox one, passed as the whole object so an unknown key is refused instead of stripped. A schema error reads in Zod's words. Every other answer is the text `hashes mcp` gives.

`src/mcp.ts` is the one file the site loads that imports npm: `@agntn/tools` and `@modelcontextprotocol/server`. Both are dependencies here, pinned to the root's versions and listed in `vite.resolve.dedupe`. They run on the worker only, so they stay out of `optimizeDeps`. On the `cloudflare_module` preset the toolkit hands its server to `createMcpHandler` from `agents`, which tells an SDK v1 server apart with `instanceof`. pnpm installs one copy of `@modelcontextprotocol/sdk` per `zod` peer it resolves, so the toolkit and `agents` can each get their own and every request fails with "createMcpHandler received an unsupported server". `nitro.alias` points every import of the SDK at the copy in `docs/node_modules`. Keep it until both resolve the same one.

The worker hashes whatever an MCP client sends it and keeps none of it. The pages still compute everything in the tab, which is what the footer promises.

## Live values

- Every number on the landing, in the rosters and on the algorithm pages comes from the library at render time. `ALGORITHMS` in `app/utils/algorithms.ts` maps `builtinAlgorithms` through `create(name).info()`. An algorithm added to the library shows up in the rosters and the registry grid by itself; its icon, blurb and the chains that use it need one line in `PRESENTATION`, which the type requires.
- `useLandingHash` hashes `hello world` and the same text with one bit flipped through every digest, for the avalanche panel, the file, the verdict and the tool call. The KDFs stay out of that walk, since each step would run their full cost in the page.
- Every text a tool would hand a model, in the `03 Full tool response` rows and the playground, comes from `src/tool-operations.ts` through the `#tool-operations` alias. The page runs the executors the MCP server runs, not a copy.
- The counts in prose (the headline, the OG image, the SEO description, the playground) come from `ALGORITHMS.length`, `HMAC_COUNT` and `FAMILIES` through `spellOut`. Frontmatter and `content/` can't call a function, so they never state a count. `::algorithm-roster` goes where a list would.
- The samples are deterministic, so SSR and the client agree and hydration doesn't flicker. Keep it that way. No `Math.random`, no clock inside a computed, and no KDF without a salt on a page: it would draw a new one on the client.
- `ownOptions` in `app/utils/algorithms.ts` leaves out `rounds` and `chain`, which every fixed digest takes, so the rosters, the registry tooltips and the OG chips show only what sets an algorithm apart. The playground reads `callOptions`, which keeps them.
- `SAMPLE_OPTIONS` gives the KDF pages and the playground chips a fixed salt and a small cost. The real defaults (600000 PBKDF2 rounds, scrypt at N 16384) take seconds in a tab.
- `HashesPlayground.vue` reads the deep link through a `watch(route.query)` registered in `onMounted` that fires once, the ciphers way. A prerendered page hydrates with an empty `route.query` and Nuxt restores the address only afterwards. Reading `window.location.search` in `onMounted` worked on `nuxt dev` and did nothing on the deployed worker. It writes state back with `router.replace` on every change and runs a call 250 ms after the form stops changing, so a KDF at its real cost blocks once, not on every key.
- The playground catches `HashError` and shows the class name and the message. Anything else is a bug in the library and belongs there, not in a try/catch here.
- The FNV-1a file on the landing (`LandingCustom.vue`) is a literal. Its comment `e40c292c` was checked by running the file against the library; check it again if you touch it.

## SEO

- `seo.schema` in `app/app.config.ts` emits the landing JSON-LD: `WebSite`, the agntn `Organization` as publisher, and a free `SoftwareApplication` with `sameAs` on GitHub and npm.
- `server/routes/sitemap.xml.ts` wraps the Docus sitemap and appends the Vue pages listed in `PAGES`; a new page under `app/pages/` goes there too.
- `public/favicon.svg` is the source, the PNGs and the `.ico` are cut from it with ImageMagick.

## OG images

- `app/components/OgImage/Docs.takumi.vue` and `Landing.takumi.vue` override the Docus templates and are rendered by Takumi at build time. Takumi has no CSS variables, so the theme colours are repeated there as literals. An algorithm page's card is built from its `info()`, not from the description.
- `app/assets/fonts.css` declares the Figtree and Fira Code TTFs in `public/fonts`, which is where nuxt-og-image reads them.
- Descriptions go without commas and without a trailing period: Docus puts them in the OG file name, where a comma is a separator and `..png` is skipped without a word. A `: ` in a frontmatter description is a YAML mapping and the page vanishes from the prerender.

## Constraints

- Text a visitor types into the playground is rendered as text, through interpolation or a `<pre>`. Never `v-html`, never evaluate.
- The sidebar takes a guide page's icon from `NAV_ICONS` in `app/composables/useSubNavigation.ts`, not from its frontmatter, so a new page goes there too.
- Every vector quoted in `content/` came out of the library in `src/`. Check a new one the same way, and against an outside reference where one exists.
- The site makes no network request for its own work and stays that way. The footer says so.
