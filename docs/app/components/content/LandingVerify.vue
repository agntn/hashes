<script setup lang="ts">
import { create } from "@agntn/hashes";
import { SAMPLE_INPUT, type LandingSample } from "../../composables/useLandingHash";
import { verifyAnswer } from "../../utils/tools";

const props = defineProps<{ sample: LandingSample }>();
const emit = defineEmits<{ pause: [paused: boolean] }>();

const slug = computed(() => props.sample.entry.slug);

/** The digest in base64, and the same text lowercased: same letters, other bytes. */
const base64 = computed(() =>
  String(create(slug.value).hash(SAMPLE_INPUT, { encoding: "base64" }).digest),
);
const lowered = computed(() => base64.value.toLowerCase());
const upper = computed(() => props.sample.digest.toUpperCase());

/** Both checks through the executor `hashes_verify` runs, so the verdicts are the tool's own. */
const hex = computed(() =>
  verifyAnswer({ algorithm: slug.value, input: SAMPLE_INPUT, expected: upper.value }),
);
const b64 = computed(() =>
  verifyAnswer({
    algorithm: slug.value,
    input: SAMPLE_INPUT,
    expected: lowered.value,
    encoding: "base64",
  }),
);
const rows = computed(() => [
  { encoding: "hex", expected: upper.value, match: hex.value.match },
  { encoding: "base64", expected: lowered.value, match: b64.value.match },
]);

/**
 * Decodes base64 to bytes with `atob`, which the browser and Node both have.
 *
 * @param {string} text - Base64 text.
 * @returns {number[]} The bytes.
 */
function base64Bytes(text: string): number[] {
  return [...atob(text)].map((character) => character.codePointAt(0)!);
}

/** One tick per digest byte, open where the lowercased base64 names another byte. */
const ticks = computed(() => {
  const want = base64Bytes(lowered.value);
  return base64Bytes(base64.value).map((byte, index) => byte !== want[index]);
});
const differing = computed(() => ticks.value.filter(Boolean).length);

const title = computed(() => `hashes_verify("${slug.value}", "${SAMPLE_INPUT}", base64)`);
const playground = computed(
  () =>
    `/playground?op=verify&algorithm=${slug.value}&input=${encodeURIComponent(SAMPLE_INPUT)}&expected=${encodeURIComponent(lowered.value)}&encoding=base64`,
);
</script>

<template>
  <section
    class="tool-console landing-verify"
    aria-label="One digest checked in hex and in base64"
    @mouseenter="emit('pause', true)"
    @mouseleave="emit('pause', false)"
    @focusin="emit('pause', true)"
    @focusout="emit('pause', false)"
  >
    <span class="console-cross console-cross-tl" aria-hidden="true">+</span>
    <span class="console-cross console-cross-br" aria-hidden="true">+</span>
    <header class="console-bar">
      <UTooltip :text="title">
        <span class="console-title verify-call" tabindex="0"
          ><span class="console-tag">Call</span>hashes_verify(<span class="tok-str"
            >"{{ slug }}"</span
          >, <span class="tok-str">"{{ SAMPLE_INPUT }}"</span>, …)</span
        >
      </UTooltip>
      <span class="console-meta">hex · base64 · every byte</span>
      <span class="console-mark" aria-hidden="true" />
    </header>
    <div class="console-ruler" aria-hidden="true">
      <span :key="slug" class="console-cursor" />
    </div>

    <!-- The verdict on the crosses grid, then both checks and a tick per digest byte. -->
    <div class="verify-subject">
      <div :key="slug" class="console-scan" aria-hidden="true" />
      <div class="verify-identity">
        <ConsoleReticle :key="slug" icon="i-lucide-check-check" />
        <div class="verify-name">
          <span class="console-label">Verdict / <span class="console-label-key">{{ slug }}</span></span>
          <h3>same letters, <span class="verify-hit">other bytes</span></h3>
          <p class="console-about">
            Hex ignores case, so the uppercase digest matches. Lowercase the base64 and it spells
            a different digest.
          </p>
        </div>
      </div>
      <div class="console-readout">
        <ol :key="slug" class="console-animate verify-rows">
          <li
            v-for="(row, index) in rows"
            :key="row.encoding"
            :data-hit="row.match ? '' : undefined"
            :style="{ animationDelay: `${index * 45}ms` }"
          >
            <span class="verify-encoding">{{ row.encoding }}</span>
            <UTooltip :text="row.expected">
              <span class="verify-expected" tabindex="0">{{ row.expected }}</span>
            </UTooltip>
            <UBadge
              :color="row.match ? 'primary' : 'error'"
              variant="outline"
              :label="row.match ? 'match' : 'mismatch'"
            />
          </li>
        </ol>
        <div
          class="console-gauge"
          :aria-label="`${differing} of ${ticks.length} digest bytes differ in the lowercased base64`"
        >
          <span class="console-ticks" aria-hidden="true">
            <span
              v-for="(open, index) in ticks"
              :key="index"
              :class="open ? 'console-tick-open' : 'console-tick-closed'"
              :style="{ animationDelay: `${index * 12}ms` }"
            />
          </span>
          <span class="console-gauge-read">{{ differing }} of {{ ticks.length }} bytes differ</span>
        </div>
      </div>
    </div>

    <ConsoleResponse :title="title" :text="b64.text" />

    <footer class="console-footer console-footer-plain">
      <span>In your browser / no network</span>
      <NuxtLink :to="playground" class="verify-link"
        ><span aria-hidden="true">→ </span>check your own digest</NuxtLink
      >
    </footer>
  </section>
</template>

<style scoped>
.verify-call {
  min-width: 0;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.verify-subject {
  position: relative;
  display: grid;
  gap: 16px;
  padding: 18px 20px 20px;
  background-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='36' height='36'%3E%3Cpath d='M16 18h4m-2-2v4' fill='none' stroke='%23818a94' stroke-opacity='.1'/%3E%3C/svg%3E");
  background-size: 36px 36px;
  background-position: 24px 20px;
}
.verify-subject > :not(.console-scan) {
  position: relative;
}
.verify-identity {
  display: grid;
  grid-template-columns: 76px minmax(0, 1fr);
  gap: 16px;
  align-items: center;
}
.verify-name {
  min-width: 0;
}
.verify-name h3 {
  margin: 4px 0 6px;
  font-family: var(--font-mono);
  font-size: 20px;
  font-weight: 400;
  line-height: 1.25;
  color: var(--ui-text-highlighted);
}
.verify-hit {
  color: var(--console-accent);
}
.verify-name .console-about {
  font-size: 14px;
}
.verify-rows {
  display: grid;
  margin: 0;
  padding: 0;
  list-style: none;
}
/* One row per check: the encoding, the expected digest on one line, the verdict. A match carries the accent edge. */
.verify-rows > li {
  display: grid;
  grid-template-columns: 3.75rem minmax(0, 1fr) auto;
  gap: 12px;
  align-items: center;
  padding: 8px 12px;
  font-size: 12px;
}
.verify-rows > li + li {
  border-top: 1px solid var(--console-line);
}
.verify-rows > li[data-hit] {
  background: color-mix(in srgb, var(--ui-primary) 5%, var(--ui-bg));
  box-shadow: inset 2px 0 0 var(--console-accent);
}
.verify-encoding {
  color: var(--ui-text-dimmed);
}
.verify-expected {
  display: block;
  min-width: 0;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
  color: var(--ui-text-muted);
}
.verify-link {
  margin-left: auto;
  color: var(--ui-text-highlighted);
}
.verify-link:hover {
  color: var(--console-accent);
}
.verify-link:focus-visible {
  outline: 1px solid var(--ui-primary);
  outline-offset: 3px;
}
@media (width < 400px) {
  .verify-subject {
    padding-inline: 14px;
  }
  .verify-identity {
    grid-template-columns: 64px minmax(0, 1fr);
    gap: 12px;
  }
}
</style>
