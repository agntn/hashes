<script setup lang="ts">
import { hashCategories } from "@agntn/hashes";
import type { LandingSample } from "../../composables/useLandingHash";
import { ALGORITHMS, digestBits, ownOptions, type AlgorithmEntry } from "../../utils/algorithms";

const props = defineProps<{ sample: LandingSample }>();
const emit = defineEmits<{ pause: [paused: boolean] }>();

type State = "current" | "kin" | "other";

/** One band per category, a cell per algorithm in listing order; the node says how it relates to the sample. */
const bands = computed(() =>
  hashCategories.map((category) => ({
    category,
    cells: ALGORITHMS.filter((entry) => entry.info.category === category).map((entry) => ({
      entry,
      state: (entry.slug === props.sample.entry.slug
        ? "current"
        : entry.info.digestLength !== undefined &&
            entry.info.digestLength === props.sample.entry.info.digestLength
          ? "kin"
          : "other") as State,
    })),
  })),
);

/**
 * What a cell's tooltip says: the digest size, HMAC and the options beyond encoding and key.
 *
 * @param {AlgorithmEntry} entry - A registered algorithm.
 * @returns {string} One line.
 */
function about(entry: AlgorithmEntry): string {
  const options = ownOptions(entry.info).map((option) => option.name + (option.required ? "" : "?"));
  const parts = [entry.info.label, digestBits(entry.info), entry.info.hmac ? "HMAC" : "no HMAC"];
  return [...parts, ...(options.length ? [options.join(", ")] : [])].join(" · ");
}
</script>

<template>
  <section
    class="tool-console console-wide landing-registry"
    aria-label="Every algorithm in the registry"
    @mouseenter="emit('pause', true)"
    @mouseleave="emit('pause', false)"
    @focusin="emit('pause', true)"
    @focusout="emit('pause', false)"
  >
    <span class="console-cross console-cross-tl" aria-hidden="true">+</span>
    <span class="console-cross console-cross-br" aria-hidden="true">+</span>

    <header class="console-bar">
      <span class="console-title"><span class="console-tag">Call</span>algorithms()</span>
      <span class="console-meta"
        >{{ ALGORITHMS.length }} names ·
        {{ bands.map((band) => `${band.cells.length} ${band.category}`).join(" · ") }}</span
      >
      <span class="console-mark" aria-hidden="true" />
    </header>
    <div class="console-ruler" aria-hidden="true">
      <span :key="sample.entry.slug" class="console-cursor" />
    </div>

    <div v-for="band in bands" :key="band.category" class="registry-band">
      <p class="console-label console-rule-title">
        <span
          ><span class="console-label-key">{{ band.category }}</span>&#32;<span aria-hidden="true"
            >[ {{ band.cells.length }} ]</span
          ></span
        >
        <span class="console-mark" aria-hidden="true" />
      </p>
      <ul class="registry-cells">
        <li v-for="cell in band.cells" :key="cell.entry.slug">
          <UTooltip :text="about(cell.entry)">
            <NuxtLink
              :to="cell.entry.to"
              class="registry-cell"
              :data-state="cell.state"
              :aria-label="about(cell.entry)"
            >
              <UIcon :name="cell.entry.icon" class="registry-icon" aria-hidden="true" />
              <span class="registry-key">{{ cell.entry.slug }}</span>
              <span class="registry-node" aria-hidden="true" />
            </NuxtLink>
          </UTooltip>
        </li>
      </ul>
    </div>

    <footer class="console-footer console-footer-plain">
      <span class="registry-legend"
        ><span class="registry-node" data-state="current" aria-hidden="true" /> in the panels now
        <span class="registry-node" data-state="kin" aria-hidden="true" /> same digest size</span
      >
      <NuxtLink to="/algorithms" class="registry-link"
        ><span aria-hidden="true">→ </span>every algorithm, with size, HMAC and options</NuxtLink
      >
    </footer>
  </section>
</template>

<style scoped>
.registry-band {
  padding: 14px 20px 16px;
  border-top: 1px solid var(--console-line);
}
.registry-band:first-of-type {
  border-top: 0;
}
.registry-band > .console-rule-title {
  margin: 0 0 12px;
}
/* A cell per algorithm: glyph, name, node. The state rides on the node and the name, never a word in every cell. */
.registry-cells {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(9rem, 1fr));
  gap: 4px;
  margin: 0;
  padding: 0;
  list-style: none;
}
.registry-cell {
  display: grid;
  grid-template-columns: 14px minmax(0, 1fr) 6px;
  gap: 8px;
  align-items: center;
  padding: 6px 9px;
  box-shadow: inset 0 0 0 1px var(--console-line);
  transition: box-shadow 0.3s ease;
}
.registry-icon {
  width: 14px;
  height: 14px;
  color: var(--ui-text-dimmed);
  transition: color 0.3s ease;
}
.registry-key {
  overflow: hidden;
  font-family: var(--font-mono);
  font-size: 12px;
  text-overflow: ellipsis;
  white-space: nowrap;
  color: var(--ui-text-muted);
  transition: color 0.3s ease;
}
.registry-node {
  display: inline-block;
  width: 6px;
  height: 6px;
  box-shadow: inset 0 0 0 1px var(--console-line);
}
.registry-cell[data-state="kin"] .registry-key,
.registry-cell[data-state="current"] .registry-key {
  color: var(--ui-text-highlighted);
}
.registry-node[data-state="kin"],
.registry-cell[data-state="kin"] .registry-node {
  box-shadow: inset 0 0 0 1px var(--console-accent);
}
.registry-cell[data-state="current"] {
  box-shadow: inset 0 0 0 1px color-mix(in srgb, var(--console-accent) 55%, transparent);
}
.registry-cell[data-state="current"] .registry-icon {
  color: var(--console-accent);
}
.registry-node[data-state="current"],
.registry-cell[data-state="current"] .registry-node {
  background: var(--console-accent);
  box-shadow: none;
}
.registry-cell:hover {
  box-shadow: inset 0 0 0 1px var(--console-accent);
}
.registry-cell:hover .registry-key {
  color: var(--console-accent);
}
.registry-cell:focus-visible {
  outline: 1px solid var(--ui-primary);
  outline-offset: 2px;
}
.registry-legend {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  white-space: nowrap;
}
.registry-legend > .registry-node:not(:first-child) {
  margin-left: 8px;
}
.registry-link {
  margin-left: auto;
  color: var(--ui-text-highlighted);
}
.registry-link:hover {
  color: var(--console-accent);
}
.registry-link:focus-visible {
  outline: 1px solid var(--ui-primary);
  outline-offset: 3px;
}
@media (width < 640px) {
  .registry-legend {
    display: none;
  }
}
@media (width < 400px) {
  .registry-band {
    padding-inline: 14px;
  }
  .registry-cells {
    grid-template-columns: repeat(auto-fill, minmax(8rem, 1fr));
  }
}
@media (prefers-reduced-motion: reduce) {
  .registry-cell,
  .registry-icon,
  .registry-key {
    transition: none;
  }
}
</style>
