<script setup lang="ts">
import { create } from "@agntn/hashes";
import { SAMPLE_INPUT } from "../../composables/useLandingHash";
import {
  ALGORITHMS,
  SAMPLE_OPTIONS,
  algorithmEntry,
  digestBits,
  familyLabel,
  registryPosition,
  securityParts,
} from "../../utils/algorithms";
import { optionFlags, optionLiteral, shellArg } from "../../utils/format";
import { algorithmsText } from "../../utils/tools";

const props = defineProps<{ name: string }>();

const entry = computed(() => algorithmEntry(props.name));
const position = computed(() => registryPosition(props.name));
const security = computed(() => (entry.value ? securityParts(entry.value.info) : undefined));
const sampleOptions = computed(() => (entry.value ? (SAMPLE_OPTIONS[entry.value.slug] ?? {}) : {}));

/** The options in the order `info()` declares them; the gauge has one tick per option, required open. */
const options = computed(() =>
  (entry.value?.info.options ?? []).map((option) => ({
    ...option,
    requirement: option.required
      ? "required"
      : option.default === undefined || option.default === ""
        ? "optional"
        : `default ${option.default}`,
  })),
);
const required = computed(() => options.value.filter((option) => option.required).length);
/** Other algorithms the library files under the same family, as links. */
const kin = computed(() =>
  ALGORITHMS.filter(
    (algorithm) => algorithm.info.family === entry.value?.info.family && algorithm.slug !== props.name,
  ),
);

/** The sample input's digest in hex and base64, computed here with the page's own options. */
const digests = computed(() => {
  if (!entry.value) return [];
  const algorithm = create(entry.value.slug);
  return (["hex", "base64"] as const).map((encoding) => ({
    encoding,
    digest: String(algorithm.hash(SAMPLE_INPUT, { encoding, ...sampleOptions.value }).digest),
  }));
});
const call = computed(() => {
  const literal = optionLiteral(sampleOptions.value);
  return `hash("${SAMPLE_INPUT}"${literal ? `, ${literal}` : ""})`;
});

const cli = computed(() => {
  const algorithm = entry.value;
  if (!algorithm) return "";
  const flags = optionFlags(sampleOptions.value);
  return `hashes ${algorithm.slug} ${shellArg(SAMPLE_INPUT)}${flags ? ` ${flags}` : ""}`;
});
const playground = computed(() => {
  const algorithm = entry.value;
  if (!algorithm) return "/playground";
  const query = new URLSearchParams({ op: "hash", algorithm: algorithm.slug, input: SAMPLE_INPUT });
  for (const [name, value] of Object.entries(sampleOptions.value)) query.set(name, String(value));
  return `/playground?${query.toString()}`;
});

const text = computed(() => (entry.value ? algorithmsText({ algorithm: entry.value.slug }) : ""));
const title = computed(() => `hash_algorithms("${props.name}")`);
</script>

<template>
  <section v-if="entry" class="tool-console console-wide not-prose my-6" aria-label="Algorithm record">
    <span class="console-cross console-cross-tl" aria-hidden="true">+</span>
    <span class="console-cross console-cross-br" aria-hidden="true">+</span>

    <header class="console-bar">
      <span class="console-title"
        ><span class="console-tag">ID</span>{{ entry.slug
        }}<span class="console-file"
          >{{ String(position).padStart(2, "0") }} / {{ ALGORITHMS.length }}</span
        ></span
      >
      <span class="console-meta">{{ entry.info.family }} · {{ digestBits(entry.info) }}</span>
      <span class="console-mark" aria-hidden="true" />
    </header>
    <div class="console-ruler" aria-hidden="true"><span class="console-cursor" /></div>

    <div class="console-band console-subject-band">
      <div class="console-scan" aria-hidden="true" />
      <div class="console-identity-block">
        <ConsoleReticle :key="entry.slug" :icon="entry.icon" />
        <div class="console-name">
          <span class="console-label">Hash / {{ familyLabel(entry.info.family) }}</span>
          <h3>{{ entry.info.label }}</h3>
          <p class="console-about">{{ entry.blurb }}.</p>
        </div>
      </div>

      <div class="console-readout">
        <svg class="console-link" viewBox="0 0 32 40" fill="none" aria-hidden="true">
          <circle cx="3" cy="12" r="2.5" />
          <path d="M5.5 12H14L22 20H32" />
        </svg>
        <dl class="console-readout-rows">
          <div>
            <dt>Digest</dt>
            <dd class="console-accent">
              <span class="alg-line">{{
                entry.info.digestLength === undefined
                  ? "keyLength you pick"
                  : `${digestBits(entry.info)} · ${entry.info.digestLength} bytes`
              }}</span>
            </dd>
          </div>
          <div>
            <dt>HMAC</dt>
            <dd>
              <span class="alg-line" :class="{ 'alg-none': !entry.info.hmac }">{{
                entry.info.hmac ? "takes a key" : "no key mode"
              }}</span>
            </dd>
          </div>
          <div>
            <dt>Security</dt>
            <dd>
              <UTooltip v-if="security" :text="security.full">
                <span class="alg-line" tabindex="0">{{ security.short }}</span>
              </UTooltip>
              <span v-else class="alg-none">not stated</span>
            </dd>
          </div>
          <div>
            <dt>{{ entry.usedBy ? "Used by" : "Family" }}</dt>
            <dd>
              <UTooltip v-if="entry.usedBy" :text="entry.usedBy">
                <span class="alg-line" tabindex="0">{{ entry.usedBy }}</span>
              </UTooltip>
              <span v-else class="alg-line"
                >{{ kin.length + 1 }} in {{ familyLabel(entry.info.family).toLowerCase() }}</span
              >
            </dd>
          </div>
        </dl>
        <div
          class="console-gauge"
          :aria-label="`${required} of ${options.length} options required`"
        >
          <span class="console-ticks" aria-hidden="true">
            <span
              v-for="(option, index) in options"
              :key="option.name"
              :class="option.required ? 'console-tick-open' : 'console-tick-closed'"
              :style="{ animationDelay: `${index * 12}ms` }"
            />
          </span>
          <span class="console-gauge-read"
            >{{ options.length }} {{ options.length === 1 ? "option" : "options" }}, {{ required }} required</span
          >
        </div>
      </div>
    </div>

    <div class="console-band">
      <p class="console-label console-rule-title">
        <span
          >Sample <span aria-hidden="true">[ {{ call }}, computed here ]</span></span
        >
        <span class="console-mark" aria-hidden="true" />
      </p>
      <dl class="alg-digests">
        <div v-for="row in digests" :key="row.encoding">
          <dt><span class="console-tag">{{ row.encoding }}</span></dt>
          <dd>
            <UTooltip :text="row.digest">
              <span class="alg-line alg-digest" tabindex="0">{{ row.digest }}</span>
            </UTooltip>
          </dd>
        </div>
      </dl>
    </div>

    <div v-if="options.length" class="console-band">
      <p class="console-label console-rule-title">
        <span>Options <span aria-hidden="true">[ as info() declares them ]</span></span>
        <span class="console-mark" aria-hidden="true" />
      </p>
      <dl class="alg-options">
        <div v-for="option in options" :key="option.name">
          <dt>
            <code>{{ option.name }}</code>
            <span class="alg-type">{{ option.type }}</span>
          </dt>
          <dd class="alg-requirement" :data-required="option.required ? '' : undefined">
            {{ option.requirement }}
          </dd>
          <dd class="alg-description">{{ option.description }}</dd>
        </div>
      </dl>
    </div>

    <div class="console-band">
      <p class="console-label console-rule-title">
        <span>Access <span aria-hidden="true">[ library · CLI · playground ]</span></span>
        <span class="console-mark" aria-hidden="true" />
      </p>
      <dl class="alg-leads">
        <dd class="console-lead">
          <span class="console-tag">Create</span>
          <code class="alg-code"
            ><span class="tok-fn">create</span>(<span class="tok-str">"{{ entry.slug }}"</span>)</code
          >
          <span class="console-leader" aria-hidden="true" />
        </dd>
        <dd class="console-lead">
          <span class="console-tag">CLI</span>
          <UTooltip :text="cli">
            <code class="alg-code" tabindex="0"><span class="tok-fn">hashes</span> {{ cli.slice(7) }}</code>
          </UTooltip>
          <span class="console-leader" aria-hidden="true" />
        </dd>
        <dd class="console-lead">
          <span class="console-tag">Try</span>
          <NuxtLink :to="playground"
            >playground<span class="alg-dim"> with the sample above</span></NuxtLink
          >
          <span class="console-leader" aria-hidden="true" />
        </dd>
        <dd v-if="kin.length" class="console-lead">
          <span class="console-tag">Kin</span>
          <span class="alg-kin"
            ><template v-for="(other, index) in kin.slice(0, 4)" :key="other.slug"
              ><NuxtLink :to="other.to">{{ other.slug }}</NuxtLink
              ><template v-if="index < Math.min(kin.length, 4) - 1">, </template></template
            ><span v-if="kin.length > 4" class="alg-dim"> +{{ kin.length - 4 }}</span></span
          >
          <span class="console-leader" aria-hidden="true" />
        </dd>
      </dl>
    </div>

    <ConsoleResponse :title="title" :text="text" />

    <footer class="console-footer console-footer-plain">
      <ul class="console-links">
        <li>
          <NuxtLink to="/algorithms"><span aria-hidden="true">→ </span>All algorithms</NuxtLink>
        </li>
        <li>
          <NuxtLink to="/guide/hashing"><span aria-hidden="true">→ </span>Hashing</NuxtLink>
        </li>
      </ul>
      <span class="console-meta">in your browser / no network</span>
    </footer>
  </section>
</template>

<style scoped>
.alg-none {
  color: var(--ui-text-dimmed);
}
/* Values stay on one line for every algorithm; the whole value is in the tooltip. */
.alg-line {
  display: block;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}
section :deep(.console-readout-rows > div) {
  grid-template-columns: 6.5rem minmax(0, 1fr);
}
/* One row per sample digest: the encoding tag, then the digest on one line with the rest in the tooltip. */
.alg-digests {
  display: grid;
  gap: 6px;
  margin: 0;
}
.alg-digests > div {
  display: grid;
  grid-template-columns: 4.5rem minmax(0, 1fr);
  gap: 12px;
  align-items: center;
}
.alg-digests dt > .console-tag {
  margin: 0;
}
.alg-digests dd {
  min-width: 0;
  margin: 0;
}
.alg-digest {
  font-family: var(--font-mono);
  font-size: 13px;
  color: var(--ui-text-highlighted);
}
/* One row per option: the name and its type, whether it is required, then what it does in the reading face. */
.alg-options {
  display: grid;
  margin: 0;
}
.alg-options > div {
  display: grid;
  grid-template-columns: 11rem 7.5rem minmax(0, 1fr);
  gap: 4px 16px;
  align-items: baseline;
  padding: 8px 0;
}
.alg-options > div + div {
  border-top: 1px solid var(--console-line);
}
.alg-options dt {
  display: flex;
  gap: 8px;
  align-items: baseline;
  min-width: 0;
}
.alg-options code {
  font-family: var(--font-mono);
  font-size: 13px;
  color: var(--ui-text-highlighted);
}
.alg-type {
  font-size: 10px;
  letter-spacing: 0.08em;
  text-transform: uppercase;
  color: var(--ui-text-dimmed);
}
.alg-requirement {
  margin: 0;
  font-size: 12px;
  color: var(--ui-text-muted);
}
.alg-requirement[data-required] {
  color: var(--console-accent);
}
.alg-description {
  margin: 0;
  font-family: var(--font-sans);
  font-size: 14px;
  line-height: 1.5;
  color: var(--ui-text-muted);
}
.alg-code {
  min-width: 0;
  overflow: hidden;
  font: inherit;
  text-overflow: ellipsis;
  white-space: nowrap;
  color: var(--ui-text-highlighted);
}
.alg-dim {
  color: var(--ui-text-dimmed);
}
.console-lead > a:hover .alg-dim {
  color: inherit;
}
.alg-kin {
  min-width: 0;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.alg-kin a:hover {
  color: var(--console-accent);
}
.alg-leads {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(min(100%, 20rem), 1fr));
  gap: 0 28px;
  margin: 0;
}
.alg-leads > .console-lead {
  margin: 0 0 8px;
  flex-wrap: nowrap;
  min-width: 0;
}
@media (width < 640px) {
  .alg-leads .console-leader {
    display: none;
  }
  .alg-options > div {
    grid-template-columns: minmax(0, 1fr) auto;
  }
  .alg-description {
    grid-column: 1 / -1;
  }
}
</style>
