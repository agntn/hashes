<script setup lang="ts">
import {
  FLIPPED_INPUT,
  SAMPLE_INPUT,
  type LandingSample,
} from "../../composables/useLandingHash";
import { ALGORITHMS, digestBits, familyLabel, registryPosition } from "../../utils/algorithms";

const props = defineProps<{ sample: LandingSample; samples: readonly LandingSample[] }>();
const emit = defineEmits<{ step: [delta: number]; pause: [paused: boolean] }>();

const { copied, copy } = useCopied();

const entry = computed(() => props.sample.entry);
const call = computed(() => `create("${entry.value.slug}").hash("${SAMPLE_INPUT}")`);

/** The two inputs as cells; the one character that differs is the one the flipped row lights. */
const inputCells = [...SAMPLE_INPUT];
const flippedCells = [...FLIPPED_INPUT];
const flippedAt = inputCells.findIndex((cell, index) => cell !== flippedCells[index]);
const flipByte = SAMPLE_INPUT.codePointAt(flippedAt)!;
const flipNote = `0x${flipByte.toString(16)} → 0x${(flipByte ^ 1).toString(16)}`;

/** The flipped digest split into hex digits, each marked when it differs from the first digest. */
const flippedDigits = computed(() =>
  [...props.sample.flipped].map((digit, index) => ({
    digit,
    moved: digit !== props.sample.digest[index],
  })),
);

/** The widest digest the walk shows, in bits: the grid keeps room for it, so the band never jumps. */
const widest = Math.max(...props.samples.map((sample) => sample.changed.length));
const slots = computed(() =>
  Array.from({ length: widest }, (_, index) => props.sample.changed[index]),
);

const bits = computed(() => props.sample.changed.length);
const share = computed(() => ((props.sample.changedCount / bits.value) * 100).toFixed(1));

/** One tick per registered algorithm, the sample's family open. */
const ticks = computed(() =>
  ALGORITHMS.map((algorithm) => ({
    slug: algorithm.slug,
    open: algorithm.info.family === entry.value.info.family,
  })),
);
const kin = computed(() => ticks.value.filter((tick) => tick.open).length);
</script>

<template>
  <section
    class="tool-console console-wide landing-avalanche"
    aria-label="Two inputs one bit apart through one algorithm"
    @mouseenter="emit('pause', true)"
    @mouseleave="emit('pause', false)"
    @focusin="emit('pause', true)"
    @focusout="emit('pause', false)"
  >
    <span class="console-cross console-cross-tl" aria-hidden="true">+</span>
    <span class="console-cross console-cross-br" aria-hidden="true">+</span>

    <header class="console-bar">
      <UTooltip :text="call">
        <span class="console-title avalanche-call" tabindex="0"
          ><span class="console-tag">Call</span>create(<span class="tok-str"
            >"{{ entry.slug }}"</span
          >).hash(<span class="tok-str">"{{ SAMPLE_INPUT }}"</span>)</span
        >
      </UTooltip>
      <span class="console-meta"
        >{{ familyLabel(entry.info.family).toLowerCase() }} ·
        {{ String(registryPosition(entry.slug)).padStart(2, "0") }} / {{ ALGORITHMS.length }}</span
      >
      <span class="console-mark" aria-hidden="true" />
    </header>
    <div class="console-ruler" aria-hidden="true">
      <span :key="entry.slug" class="console-cursor" />
    </div>

    <div class="console-band console-subject-band avalanche-subject">
      <div :key="entry.slug" class="console-scan" aria-hidden="true" />
      <div class="avalanche-left">
        <div class="console-identity-block">
          <ConsoleReticle :key="entry.slug" :icon="entry.icon" />
          <!-- Every sample's name sits in the same cell, hidden, so the band keeps the tallest one's height. -->
          <div class="avalanche-names">
            <div
              v-for="other in samples"
              :key="other.entry.slug"
              class="console-name"
              :class="{ 'avalanche-sizer': other.entry.slug !== entry.slug }"
              :aria-hidden="other.entry.slug !== entry.slug ? 'true' : undefined"
            >
              <span class="console-label"
                >Hash / <span class="console-label-key">{{ other.entry.info.family }}</span></span
              >
              <h3>{{ other.entry.info.label }}</h3>
              <p class="console-about">{{ other.entry.blurb }}.</p>
            </div>
          </div>
        </div>

        <div class="avalanche-board">
          <p class="console-label console-rule-title">
            <span>Avalanche <span aria-hidden="true">[ one bit in, every bit it moved ]</span></span>
            <span class="console-mark" aria-hidden="true" />
            <UButton
              color="neutral"
              variant="subtle"
              :icon="copied === 'digest' ? 'i-lucide-check' : 'i-lucide-copy'"
              :label="copied === 'digest' ? 'copied' : 'copy'"
              :aria-label="copied === 'digest' ? 'Copied' : 'Copy the digest'"
              @click="copy('digest', sample.digest)"
            />
          </p>

          <div class="avalanche-row">
            <span class="console-tag">In</span>
            <span class="avalanche-cells" :aria-label="SAMPLE_INPUT">
              <span
                v-for="(cell, index) in inputCells"
                :key="index"
                class="avalanche-cell"
                :data-blank="cell === ' ' ? '' : undefined"
                aria-hidden="true"
                >{{ cell === " " ? "·" : cell }}</span
              >
            </span>
            <span class="avalanche-count">{{ inputCells.length }} bytes</span>
          </div>
          <div class="avalanche-row">
            <span class="console-tag avalanche-tag-flip">Flip</span>
            <span class="avalanche-cells" :aria-label="FLIPPED_INPUT">
              <span
                v-for="(cell, index) in flippedCells"
                :key="index"
                class="avalanche-cell"
                :data-blank="cell === ' ' ? '' : undefined"
                :data-lit="index === flippedAt ? '' : undefined"
                aria-hidden="true"
                >{{ cell === " " ? "·" : cell }}</span
              >
            </span>
            <span class="avalanche-count">{{ flipNote }}</span>
          </div>

          <dl class="avalanche-digests">
            <div>
              <dt class="console-tag">Out</dt>
              <dd>
                <UTooltip :text="sample.digest">
                  <span class="avalanche-hex" tabindex="0">{{ sample.digest }}</span>
                </UTooltip>
              </dd>
            </div>
            <div>
              <dt class="console-tag avalanche-tag-flip">Out</dt>
              <dd>
                <UTooltip :text="sample.flipped">
                  <span :key="entry.slug" class="avalanche-hex" tabindex="0"
                    ><span
                      v-for="(cell, index) in flippedDigits"
                      :key="index"
                      :class="{ 'avalanche-moved': cell.moved }"
                      >{{ cell.digit }}</span
                    ></span
                  >
                </UTooltip>
              </dd>
            </div>
          </dl>

          <div
            :key="entry.slug"
            class="avalanche-bits"
            role="img"
            :aria-label="`${sample.changedCount} of ${bits} digest bits changed`"
          >
            <span
              v-for="(bit, index) in slots"
              :key="index"
              class="avalanche-bit"
              :data-state="bit === undefined ? 'none' : bit ? 'moved' : 'kept'"
              :style="{ animationDelay: `${Math.min(index * 2, 600)}ms` }"
            />
          </div>
        </div>
      </div>

      <div class="console-readout">
        <svg class="console-link" viewBox="0 0 32 40" fill="none" aria-hidden="true">
          <circle cx="3" cy="12" r="2.5" />
          <path d="M5.5 12H14L22 20H32" />
        </svg>
        <dl :key="entry.slug" class="console-readout-rows console-animate">
          <div>
            <dt>Digest</dt>
            <dd>
              <span class="avalanche-line"
                >{{ digestBits(entry.info) }} · {{ entry.info.digestLength }} bytes</span
              >
            </dd>
          </div>
          <div>
            <dt>Bits moved</dt>
            <dd class="console-accent">
              <span class="avalanche-line">{{ sample.changedCount }} of {{ bits }} · {{ share }}%</span>
            </dd>
          </div>
          <div>
            <dt>HMAC</dt>
            <dd>
              <span class="avalanche-line" :class="{ 'avalanche-none': !entry.info.hmac }">{{
                entry.info.hmac ? "takes a key" : "no key mode"
              }}</span>
            </dd>
          </div>
          <div>
            <dt>{{ entry.usedBy ? "Used by" : "Family" }}</dt>
            <dd>
              <UTooltip v-if="entry.usedBy" :text="entry.usedBy">
                <span class="avalanche-line" tabindex="0">{{ entry.usedBy }}</span>
              </UTooltip>
              <span v-else class="avalanche-line">{{ entry.info.family }}</span>
            </dd>
          </div>
        </dl>
        <div
          class="console-gauge"
          :aria-label="`${kin} of ${ALGORITHMS.length} algorithms in this family`"
        >
          <span class="console-ticks" aria-hidden="true">
            <span
              v-for="(tick, index) in ticks"
              :key="tick.slug"
              :class="tick.open ? 'console-tick-open' : 'console-tick-closed'"
              :style="{ animationDelay: `${index * 12}ms` }"
            />
          </span>
          <span class="console-gauge-read">family {{ kin }} / {{ ALGORITHMS.length }}</span>
        </div>
      </div>
    </div>

    <footer class="console-footer console-footer-plain">
      <NuxtLink :to="entry.to" class="avalanche-link"
        ><span aria-hidden="true">→ </span>{{ entry.info.label }}<span> · {{ entry.to }}</span></NuxtLink
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
.avalanche-call {
  min-width: 0;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.avalanche-names {
  display: grid;
  min-width: 0;
}
.avalanche-names > .console-name {
  grid-area: 1 / 1;
}
.avalanche-sizer {
  visibility: hidden;
}
.avalanche-line {
  display: block;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.avalanche-none {
  color: var(--ui-text-dimmed);
}
.landing-avalanche :deep(.console-readout-rows > div) {
  grid-template-columns: 6.5rem minmax(0, 1fr);
}
/* The left column: the algorithm, then both inputs and what came out right under it. */
.avalanche-left {
  display: grid;
  gap: 18px;
  min-width: 0;
}
.avalanche-board {
  display: grid;
  gap: 8px;
  min-width: 0;
}
.avalanche-board > .console-rule-title {
  margin: 0 0 2px;
}
.avalanche-row,
.avalanche-digests > div {
  display: grid;
  grid-template-columns: 3rem minmax(0, 1fr) auto;
  gap: 10px;
  align-items: center;
}
.avalanche-digests {
  display: grid;
  gap: 6px;
  margin: 6px 0 0;
}
.avalanche-digests > div {
  grid-template-columns: 3rem minmax(0, 1fr);
}
.avalanche-digests dd {
  min-width: 0;
  margin: 0;
}
.avalanche-row > .console-tag,
.avalanche-digests .console-tag {
  justify-self: start;
  margin: 0;
}
.avalanche-tag-flip {
  color: var(--console-accent);
  box-shadow: inset 0 0 0 1px color-mix(in srgb, var(--console-accent) 55%, transparent);
}
.avalanche-cells {
  display: flex;
  gap: 3px;
  min-width: 0;
  overflow: hidden;
  mask-image: linear-gradient(90deg, #000 calc(100% - 24px), transparent);
}
.avalanche-cell {
  display: grid;
  flex: none;
  place-items: center;
  min-width: 20px;
  height: 24px;
  padding: 0 3px;
  font-family: var(--font-mono);
  font-size: 12px;
  color: var(--ui-text-muted);
  background: var(--ui-bg);
  box-shadow: inset 0 0 0 1px var(--console-line);
}
.avalanche-cell[data-blank] {
  color: var(--ui-text-dimmed);
  box-shadow: inset 0 0 0 1px var(--ui-border-muted);
}
.avalanche-cell[data-lit] {
  color: var(--console-accent);
  box-shadow: inset 0 0 0 1px var(--console-accent);
}
.avalanche-count {
  font-family: var(--font-mono);
  font-size: 11px;
  letter-spacing: 0.04em;
  white-space: nowrap;
  color: var(--ui-text-dimmed);
}
.avalanche-hex {
  display: block;
  overflow: hidden;
  font-family: var(--font-mono);
  font-size: 12px;
  text-overflow: ellipsis;
  white-space: nowrap;
  color: var(--ui-text-muted);
}
.avalanche-moved {
  color: var(--console-accent);
}
/* One cell per digest bit, 64 to a row; a moved bit is open in the accent, a kept one hatched quiet. */
.avalanche-bits {
  display: grid;
  grid-template-columns: repeat(64, minmax(0, 1fr));
  gap: 2px;
  margin-top: 8px;
}
.avalanche-bit {
  aspect-ratio: 1;
  animation: avalanche-in 0.24s ease-out both;
}
.avalanche-bit[data-state="kept"] {
  background: color-mix(in srgb, var(--ui-text-muted) 22%, var(--ui-bg));
}
.avalanche-bit[data-state="moved"] {
  box-shadow: inset 0 0 0 1px var(--console-accent);
  background: color-mix(in srgb, var(--console-accent) 30%, var(--ui-bg));
}
.avalanche-bit[data-state="none"] {
  animation: none;
}
@keyframes avalanche-in {
  from {
    transform: translateY(-3px);
  }
}
/* Side by side, the readout runs as tall as the avalanche beside it; stacked, it keeps its own height. */
@container (width >= 46rem) {
  .avalanche-subject > .console-readout {
    display: grid;
    grid-template-rows: minmax(0, 1fr) auto;
    align-self: stretch;
  }
  .avalanche-subject .console-readout-rows {
    grid-auto-rows: minmax(2.5rem, 1fr);
  }
  .avalanche-subject .console-readout-rows > div {
    align-items: center;
  }
}
.avalanche-link {
  min-width: 0;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
  color: var(--ui-text-highlighted);
}
.avalanche-link > span:last-child {
  color: var(--ui-text-dimmed);
}
.avalanche-link:hover {
  color: var(--console-accent);
}
.avalanche-link:focus-visible {
  outline: 1px solid var(--ui-primary);
  outline-offset: 3px;
}
@media (width < 640px) {
  .avalanche-board > .console-rule-title > .console-mark {
    display: none;
  }
  .avalanche-bits {
    grid-template-columns: repeat(32, minmax(0, 1fr));
  }
}
@media (prefers-reduced-motion: reduce) {
  .avalanche-bit {
    animation: none;
  }
}
</style>
