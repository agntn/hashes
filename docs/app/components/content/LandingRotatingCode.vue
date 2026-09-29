<script setup lang="ts">
import { create, digestMatches } from "@agntn/hashes";
import { SAMPLE_INPUT, type LandingSample } from "../../composables/useLandingHash";
import { digestBits } from "../../utils/algorithms";
import { tokens } from "../../utils/tokens";

const props = defineProps<{ sample: LandingSample }>();
const emit = defineEmits<{ step: [delta: number]; pause: [paused: boolean] }>();

const { copied, copy } = useCopied();

/** Every algorithm gets the same fourteen lines, so the file keeps one height while the sample walks. */
const lines = computed(() => {
  const { entry, digest } = props.sample;
  const algorithm = create(entry.slug);
  const base64 = String(algorithm.hash(SAMPLE_INPUT, { encoding: "base64" }).digest);
  const upper = digest.toUpperCase();
  const match = digestMatches(algorithm.hash(SAMPLE_INPUT), upper);
  return [
    'import { create, digestMatches } from "@agntn/hashes";',
    "",
    `// ${entry.info.label}, ${entry.info.family}, ${digestBits(entry.info)}`,
    `const hash = create("${entry.slug}");`,
    "",
    `const result = hash.hash("${SAMPLE_INPUT}");`,
    `result.digest;        // "${digest}"`,
    `result.digestLength;  // ${entry.info.digestLength}`,
    "",
    `hash.hash("${SAMPLE_INPUT}", { encoding: "base64" }).digest;`,
    `// "${base64}"`,
    "",
    `const upper = "${upper}";`,
    `digestMatches(result, upper);  // ${match}, hex ignores case`,
  ];
});
</script>

<template>
  <section
    class="tool-console landing-file"
    aria-label="One algorithm, hashed and checked"
    @mouseenter="emit('pause', true)"
    @mouseleave="emit('pause', false)"
    @focusin="emit('pause', true)"
    @focusout="emit('pause', false)"
  >
    <span class="console-cross console-cross-tl" aria-hidden="true">+</span>
    <span class="console-cross console-cross-br" aria-hidden="true">+</span>

    <header class="console-bar">
      <span class="console-title file-name"
        ><span class="console-tag">File</span
        ><Transition name="hashes-roll" mode="out-in"
          ><span :key="sample.entry.slug" class="hashes-roll-slot"
            >{{ sample.entry.slug }}.ts</span
          ></Transition
        ></span
      >
      <span class="console-meta">{{ sample.entry.info.family }} · computed here</span>
      <span class="console-mark" aria-hidden="true" />
    </header>
    <div class="console-ruler" aria-hidden="true">
      <span :key="sample.entry.slug" class="console-cursor" />
    </div>

    <div class="file-body">
      <p class="console-label console-rule-title">
        <span>Digest <span aria-hidden="true">[ hash, encode, compare ]</span></span>
        <span class="console-mark" aria-hidden="true" />
        <UButton
          color="neutral"
          variant="subtle"
          :icon="copied === 'file' ? 'i-lucide-check' : 'i-lucide-copy'"
          :label="copied === 'file' ? 'copied' : 'copy'"
          :aria-label="copied === 'file' ? 'Copied' : 'Copy the file'"
          @click="copy('file', lines.join('\n'))"
        />
      </p>
      <!-- prettier-ignore -->
      <pre class="console-snippet console-lines file-lines"><code><span v-for="(line, index) in lines" :key="index"><span class="file-code"><span v-for="(token, part) in tokens(line)" :key="part" :class="token.cls">{{ token.text }}</span></span></span></code></pre>
    </div>

    <footer class="console-footer console-footer-plain">
      <NuxtLink :to="sample.entry.to" class="file-link"
        ><span aria-hidden="true">→ </span>{{ sample.entry.info.label
        }}<span> · {{ sample.entry.to }}</span></NuxtLink
      >
      <div class="console-controls" aria-label="Sample algorithms">
        <UButton
          color="neutral"
          variant="subtle"
          square
          icon="i-lucide-chevron-left"
          aria-label="Previous algorithm"
          @click="emit('step', -1)"
        />
        <span>Hash</span>
        <UButton
          color="neutral"
          variant="subtle"
          square
          icon="i-lucide-chevron-right"
          aria-label="Next algorithm"
          @click="emit('step', 1)"
        />
      </div>
    </footer>
  </section>
</template>

<style scoped>
.file-name {
  min-width: 0;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.file-name :deep(.hashes-roll-slot) {
  display: inline;
}
.file-body {
  padding: 14px 20px 16px;
}
.file-body > .console-rule-title {
  margin-bottom: 10px;
}
/* One line per code line whatever the algorithm: the number in its own column, a long value ends in an
   ellipsis there and never takes the number with it; copy hands out the whole line. */
.file-lines > code > span {
  display: grid;
  grid-template-columns: 2.25em minmax(0, 1fr);
  column-gap: 1em;
  padding-left: 0;
  text-indent: 0;
}
.file-lines > code > span::before {
  margin-right: 0;
}
.file-code {
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: pre;
}
.file-code :deep(*) {
  white-space: pre;
  overflow-wrap: normal;
}
.file-link {
  min-width: 0;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
  color: var(--ui-text-highlighted);
}
.file-link > span:last-child {
  color: var(--ui-text-dimmed);
}
.file-link:hover {
  color: var(--console-accent);
}
.file-link:focus-visible {
  outline: 1px solid var(--ui-primary);
  outline-offset: 3px;
}
@media (width < 640px) {
  .file-body > .console-rule-title > .console-mark {
    display: none;
  }
}
@media (width < 400px) {
  .file-body {
    padding-inline: 14px;
  }
  .file-body > .console-rule-title > span:first-child > span {
    display: none;
  }
}
</style>
