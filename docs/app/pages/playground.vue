<script setup lang="ts">
import { version } from "@agntn/hashes";
import { ALGORITHMS, FAMILIES, HMAC_COUNT } from "../utils/algorithms";
import { spellOut } from "../utils/format";
import { TOOLS } from "../utils/tools";

definePageMeta({ layout: "default" });

const title = "Playground";
const description = `Hash, HMAC and verify with any of the ${spellOut(ALGORITHMS.length)} algorithms, or list them. In the browser, with the same executors the CLI and the agent tools run.`;
/** The OG pipeline drops commas from its props, so the card gets a version written without them. */
const cardDescription = `Hash and HMAC and verify with any of the ${spellOut(ALGORITHMS.length)} algorithms. In the browser with the library itself.`;

useSeo({
  title,
  description,
  type: "article",
  breadcrumbs: [{ title: "Playground", path: "/playground" }],
});

defineOgImage(
  "Docs.takumi",
  { headline: "Playground", title, description: cardDescription },
  { alt: "The @agntn/hashes playground: hash, HMAC and verify in the browser" },
);
</script>

<template>
  <div class="hashes-landing not-prose">
    <header class="hashes-hero hero-page">
      <div class="hero-zone">
        <span class="hero-cross hero-cross-tl" aria-hidden="true">+</span>
        <span class="hero-cross hero-cross-tr" aria-hidden="true">+</span>
        <span class="hero-bracket hero-bracket-l" aria-hidden="true" />
        <span class="hero-bracket hero-bracket-r" aria-hidden="true" />

        <p class="console-id">
          <span class="console-id-tag">ID</span>
          <span>playground</span>
          <span class="console-id-sep" aria-hidden="true">/</span>
          <span>@agntn/hashes v{{ version }}</span>
        </p>

        <h1 class="hero-title">
          Any algorithm. <br class="playground-break" />
          <span>Computed in your tab.</span>
        </h1>
        <p class="hero-lead">
          The page imports @agntn/hashes and runs the tool executors in your browser. What you type
          never leaves the tab, and every state is a link you can paste to someone.
        </p>

        <dl class="hero-metrics">
          <div>
            <dt>Tools</dt>
            <dd>{{ TOOLS.length }}</dd>
            <dd class="hero-metric-sub">same as MCP, Pi and OMP</dd>
          </div>
          <div>
            <dt>Algorithms</dt>
            <dd>{{ ALGORITHMS.length }}</dd>
            <dd class="hero-metric-sub">{{ FAMILIES.length }} families, {{ HMAC_COUNT }} with HMAC</dd>
          </div>
          <div>
            <dt>Network</dt>
            <dd class="hero-metric-accent">0 <span>calls</span></dd>
            <dd class="hero-metric-sub">the library never asks</dd>
          </div>
        </dl>

        <p class="playground-note">
          <span class="console-tag">Note</span>
          <span
            >Nothing leaves the tab, but whatever you type does land in the address bar and in any
            link you copy. Don't paste a real password.</span
          >
        </p>
      </div>

      <div class="hero-instrument hero-instrument-keep">
        <svg class="hero-circuit" viewBox="0 0 160 56" aria-hidden="true">
          <path class="hero-circuit-rail" d="M80 0V16L96 32V56" />
          <path class="hero-circuit-live" d="M80 0V16L96 32V56" pathLength="1" />
          <path class="hero-circuit-seg" d="M96 38V48" />
          <rect class="hero-circuit-node" x="92.5" y="52.5" width="7" height="7" />
        </svg>
        <span class="hero-circuit-tag" aria-hidden="true">call</span>
        <HashesPlayground />
      </div>
    </header>
  </div>
</template>

<style scoped>
/* One sentence per line on wide screens; narrow, the title wraps where it fits. */
@media (width < 64rem) {
  .playground-break {
    display: none;
  }
}
/* The note reads as a line of the zone, like the share bar's legend on the landing: no box of its own. */
.playground-note {
  display: flex;
  justify-content: center;
  align-items: baseline;
  gap: 12px;
  max-width: 44rem;
  margin: 28px auto 0;
  font-family: var(--font-sans);
  font-size: 14px;
  line-height: 1.6;
  text-align: left;
  color: var(--ui-text-muted);
}
.playground-note > .console-tag {
  flex: none;
  margin: 0;
  color: var(--console-accent);
  box-shadow: inset 0 0 0 1px color-mix(in srgb, var(--console-accent) 55%, transparent);
}
</style>
