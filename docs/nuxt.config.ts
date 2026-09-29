import { resolve } from "node:path";
import { hashesTheme } from "./shiki-theme";

/** Bundled from the checkout's sources: a deploy needs neither dist/ nor the root node_modules. */
const librarySource = resolve(import.meta.dirname, "../src");

export default defineNuxtConfig({
  extends: ["docus"],
  /** The repo root is its own pnpm workspace; Nuxt must not treat it as this site's. */
  workspaceDir: import.meta.dirname,
  alias: {
    "@agntn/hashes": resolve(librarySource, "index.ts"),
    /** The text the agent tools answer with; besides the library it imports only typebox, a dependency here. */
    "#tool-operations": resolve(librarySource, "tool-operations.ts"),
  },
  vite: {
    build: { target: "es2024" },
    /** `../src` resolves bare imports from the repo root upward, never from docs/node_modules, unless deduped. */
    resolve: { dedupe: ["typebox"] },
    optimizeDeps: { include: ["typebox"] },
    server: {
      /** Dev serves the library from outside the workspace, which Vite refuses without this. */
      fs: { allow: [librarySource] },
    },
  },
  devtools: { enabled: false },
  telemetry: false,
  site: {
    url: "https://hashes.agntn.dev",
    name: "@agntn/hashes",
  },
  llms: {
    domain: "https://hashes.agntn.dev",
    title: "@agntn/hashes",
    description:
      "Hash, HMAC and verify with SHA-256, BLAKE3, Keccak-256, HASH160, scrypt and the rest of the registry, as a library, a CLI, an MCP server and Pi and OMP extensions. Computed locally.",
    sections: [
      {
        title: "Playground",
        description: "Hash, HMAC, verify and list the algorithms, in the browser.",
        links: [
          {
            title: "Playground",
            href: "https://hashes.agntn.dev/playground",
            description: "The library running in the page: hash_compute, hash_hmac, hash_verify and hash_algorithms.",
          },
        ],
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
  /** Docus ships an MCP endpoint that wants the Cloudflare Agents SDK on Workers. Not needed. */
  mcp: {
    enabled: false,
  },
  nitro: {
    preset: "cloudflare_module",
    compatibilityDate: "2026-09-03",
    /** Nitro compiles the server bundle for ES2019 unless told otherwise; the library uses BigInt. */
    esbuild: { options: { target: "es2024" } },
    prerender: {
      crawlLinks: true,
      routes: ["/", "/playground", "/sitemap.xml", "/robots.txt", "/llms.txt", "/llms-full.txt"],
    },
    cloudflare: {
      deployConfig: true,
      nodeCompat: true,
    },
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
