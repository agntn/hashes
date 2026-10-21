import { resolve } from "node:path";
import { hashesTheme } from "./shiki-theme";

/** Bundled from the checkout's sources: no dist/ needed, imports resolve from the root. */
const librarySource = resolve(import.meta.dirname, "../src");

/** Runtime deps of src/mcp.ts, listed in docs/ too so Vite settles on one copy. */
const libraryDependencies = ["@agntn/tools", "@modelcontextprotocol/server"];

export default defineNuxtConfig({
  extends: ["docus"],
  alias: {
    "@agntn/hashes": resolve(librarySource, "index.ts"),
    /** The text the agent tools answer with; it imports nothing beyond the library. */
    "#tool-operations": resolve(librarySource, "tool-operations.ts"),
  },
  vite: {
    build: { target: "es2024" },
    /** The playground's search worker imports the library, and only module workers split chunks. */
    worker: { format: "es" },
    resolve: {
      /** Bare imports in ../src resolve upwards from the importer and skip docs/node_modules. */
      dedupe: libraryDependencies,
    },
  },
  devtools: { enabled: false },
  telemetry: false,
  site: {
    url: "https://hashes.agntn.dev",
    name: "@agntn/hashes",
  },
  /** The playground has no markdown twin, so agents get the page itself, not a `/raw` 404. */
  agentDiscovery: {
    excludePrefixes: { extend: ["/playground"] },
  },
  /** Docus lists `content/` only and leaves app routes out, so the Vue pages come from here. */
  sitemap: {
    sources: ["/api/__sitemap__/pages"],
  },
  llms: {
    domain: "https://hashes.agntn.dev",
    title: "@agntn/hashes",
    description:
      "Hash, HMAC and verify with SHA-256, BLAKE3, Keccak-256, HASH160, scrypt and the rest of the registry, as a library, a CLI, an MCP server and Pi and OMP extensions. Computed locally.",
    sections: [
      {
        title: "MCP Server",
        description: "The tools of `hashes mcp` and the page tools of this site over Streamable HTTP.",
        links: [
          {
            title: "MCP endpoint",
            href: "https://hashes.agntn.dev/mcp",
            description:
              "Add it to any MCP client as an HTTP server, for example `claude mcp add --transport http hashes https://hashes.agntn.dev/mcp`.",
          },
        ],
      },
      {
        title: "Playground",
        description: "Hash, HMAC, verify, extend, identify, search and list the algorithms, in the browser.",
        links: [
          {
            title: "Playground",
            href: "https://hashes.agntn.dev/playground",
            description: "The library running in the page: hashes_compute, hashes_hmac_compute, hashes_verify and hashes_algorithms.",
          },
        ],
      },
      /** Agent discovery lists no pages once a section links one, so these ask, in tab order. */
      {
        title: "Guide",
        contentCollection: "docs",
        contentFilters: [{ field: "path", operator: "LIKE", value: "/guide%" }],
      },
      {
        title: "Algorithms",
        contentCollection: "docs",
        contentFilters: [{ field: "path", operator: "LIKE", value: "/algorithms%" }],
      },
    ],
  },
  /** Docus pages define their own OG images; the alt text is the one thing they leave unset. */
  ogImage: {
    defaults: {
      alt: "@agntn/hashes: hash, HMAC and verify, computed locally",
    },
  },
  icon: {
    clientBundle: {
      icons: [
        "lucide:activity",
        "lucide:arrow-down",
        "lucide:arrow-left",
        "lucide:arrow-right",
        "lucide:arrow-right-left",
        "lucide:arrow-up",
        "lucide:arrow-up-right",
        "lucide:binary",
        "lucide:blocks",
        "lucide:book-open",
        "lucide:bot",
        "lucide:calculator",
        "lucide:chart-column",
        "lucide:check",
        "lucide:check-circle",
        "lucide:chevron-down",
        "lucide:chevron-left",
        "lucide:chevron-right",
        "lucide:chevrons-up-down",
        "lucide:circle-alert",
        "lucide:circle-check",
        "lucide:circle-x",
        "lucide:columns-3",
        "lucide:copy",
        "lucide:disc-3",
        "lucide:expand",
        "lucide:external-link",
        "lucide:flask-conical",
        "lucide:flip-horizontal-2",
        "lucide:grid-2x2",
        "lucide:grid-3x3",
        "lucide:hash",
        "lucide:key-round",
        "lucide:keyboard",
        "lucide:library",
        "lucide:link",
        "lucide:list-ordered",
        "lucide:plus",
        "lucide:radio",
        "lucide:rotate-ccw",
        "lucide:rotate-ccw-key",
        "lucide:split",
        "lucide:square-sigma",
        "lucide:table",
        "lucide:terminal",
        "lucide:x",
        "simple-icons:github",
        "simple-icons:npm",
        "vscode-icons:file-type-js",
        "vscode-icons:file-type-json",
        "vscode-icons:file-type-shell",
        "vscode-icons:file-type-typescript",
      ],
    },
  },
  colorMode: {
    preference: "dark",
  },
  app: {
    head: {
      link: [
        { rel: "icon", type: "image/svg+xml", href: "/favicon.svg" },
        { rel: "apple-touch-icon", sizes: "180x180", href: "/apple-touch-icon.png" },
        { rel: "manifest", href: "/site.webmanifest" },
      ],
      meta: [
        { name: "theme-color", media: "(prefers-color-scheme: dark)", content: "#0b0d10" },
        { name: "theme-color", media: "(prefers-color-scheme: light)", content: "#eef1f4" },
        { name: "apple-mobile-web-app-title", content: "hashes" },
        { name: "author", content: "oritwoen" },
        { property: "og:locale", content: "en_US" },
      ],
    },
  },
  nitro: {
    preset: "cloudflare_module",
    compatibilityDate: "2026-09-03",
    /** Nitro compiles the server bundle for ES2019 unless told otherwise; the library uses BigInt. */
    esbuild: { options: { target: "es2024" } },
    cloudflare: {
      deployConfig: true,
      nodeCompat: true,
    },
  },
  /** Nuxt's own prerender option. The same keys under `nitro.prerender` are deprecated. */
  prerender: {
    crawlLinks: true,
    routes: ["/", "/playground", "/sitemap.xml", "/robots.txt", "/llms.txt", "/llms-full.txt"],
  },
  compatibilityDate: "2026-09-03",
  /** Fonts live in public/fonts and app/assets/fonts.css, where nuxt-og-image reads them from. */
  css: ["~/assets/fonts.css"],
  fonts: {
    families: [
      { name: "Figtree", provider: "local", weights: [400, 500] },
      { name: "Fira Code", provider: "local", weights: [400, 500] },
    ],
  },
  content: {
    database: {
      type: "d1",
      bindingName: "DB",
    },
    build: {
      markdown: {
        highlight: {
          theme: {
            default: hashesTheme,
            light: hashesTheme,
            dark: hashesTheme,
          },
        },
      },
    },
  },
});
