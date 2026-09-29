<script setup lang="ts">
import {
  HashError,
  hashCategories,
  type AlgorithmInfo,
  type HashCategory,
} from "@agntn/hashes";
import {
  INPUT_ENCODINGS,
  TEXT_ENCODINGS,
  hashAlgorithms,
  hashCompute,
  hashHmac,
  hashVerify,
  type DigestDetails,
  type VerifyDetails,
} from "#tool-operations";
import {
  ALGORITHMS,
  FAMILIES,
  SAMPLE_OPTIONS,
  algorithmEntry,
  categoryLabel,
  digestBits,
  ownOptions,
} from "../../utils/algorithms";
import { optionFlags, shellArg } from "../../utils/format";
import { jsonTokens, shellTokens } from "../../utils/tokens";

type Operation = "hash" | "hmac" | "verify" | "algorithms";

const OPERATIONS: ReadonlyArray<{ key: Operation; label: string; tool: string; about: string }> = [
  {
    key: "hash",
    label: "Hash",
    tool: "hash_compute",
    about: "The digest of the input with any algorithm. A KDF without a salt draws one and says which.",
  },
  {
    key: "hmac",
    label: "HMAC",
    tool: "hash_hmac",
    about: "A keyed digest, for the algorithms that have an HMAC mode. The rest say no.",
  },
  {
    key: "verify",
    label: "Verify",
    tool: "hash_verify",
    about: "Hash the input and compare every byte with an expected digest. Hex ignores case, base64 doesn't.",
  },
  {
    key: "algorithms",
    label: "List",
    tool: "hash_algorithms",
    about: "Every algorithm with family, category, size and HMAC, one family or category, or one algorithm's options.",
  },
];

const route = useRoute();
const router = useRouter();

const operation = ref<Operation>("hash");
const algorithmName = ref<string>("sha256");
const input = ref("hello world");
const inputEncoding = ref<(typeof INPUT_ENCODINGS)[number]>("utf8");
const encoding = ref<(typeof TEXT_ENCODINGS)[number]>("hex");
const key = ref("secret");
const keyEncoding = ref<(typeof INPUT_ENCODINGS)[number]>("utf8");
const expected = ref("");
const salt = ref("");
const values = reactive<Record<string, string>>({});
/** `hash_algorithms` lists everything when both are empty, and describes one algorithm when one is picked. */
const family = ref("");
const category = ref<HashCategory | "">("");
const describe = ref("");

const entry = computed(() => algorithmEntry(algorithmName.value) ?? ALGORITHMS[0]!);
const takesSalt = computed(() => entry.value.info.options.some((option) => option.name === "salt"));
/** Options besides encoding, key and salt: the `parameters` a tool call takes. */
const parameterFields = computed(() =>
  ownOptions(entry.value.info).filter((option) => option.name !== "salt"),
);
const usesParameters = computed(() => operation.value === "hash" || operation.value === "verify");

const algorithmItems = computed(() =>
  ALGORITHMS.filter((algorithm) => operation.value !== "hmac" || algorithm.info.hmac).map(
    (algorithm) => ({
      label: `${algorithm.info.label} · ${algorithm.slug}`,
      value: algorithm.slug,
      icon: algorithm.icon,
    }),
  ),
);
const familyItems = [
  { label: "every family", value: "" },
  ...FAMILIES.map((name) => ({ label: name, value: name })),
];
const categoryItems = [
  { label: "every category", value: "" },
  ...hashCategories.map((key) => ({ label: key, value: key })),
];
const describeItems = [
  { label: "list, no algorithm", value: "" },
  ...ALGORITHMS.map((algorithm) => ({
    label: `${algorithm.info.label} · ${algorithm.slug}`,
    value: algorithm.slug,
    icon: algorithm.icon,
  })),
];
const inputEncodingItems = INPUT_ENCODINGS.map((value) => ({ label: value, value }));
const encodingItems = TEXT_ENCODINGS.map((value) => ({ label: value, value }));

/**
 * Typed parameter values. Empty fields are left out so the algorithm applies its own defaults; a
 * number past 2^53 stays text, the way the library takes an xxHash seed without rounding it.
 */
const parameters = computed<Record<string, string | number>>(() => {
  const out: Record<string, string | number> = {};
  for (const field of parameterFields.value) {
    const raw = values[field.name]?.trim() ?? "";
    if (raw === "") continue;
    const number = Number(raw);
    out[field.name] = field.type === "number" && Number.isSafeInteger(number) ? number : raw;
  }
  return out;
});

/** The arguments exactly as a tool call would carry them; defaults are left out, like a model would. */
const toolArgs = computed((): Record<string, unknown> => {
  if (operation.value === "algorithms") {
    if (describe.value) return { algorithm: describe.value };
    return {
      ...(family.value ? { family: family.value } : {}),
      ...(category.value ? { category: category.value } : {}),
    };
  }
  const args: Record<string, unknown> = { algorithm: entry.value.slug, input: input.value };
  if (inputEncoding.value !== "utf8") args.inputEncoding = inputEncoding.value;
  if (operation.value === "hmac") {
    args.key = key.value;
    if (keyEncoding.value !== "utf8") args.keyEncoding = keyEncoding.value;
  }
  if (operation.value === "verify") args.expected = expected.value;
  if (encoding.value !== "hex") args.encoding = encoding.value;
  if (usesParameters.value && takesSalt.value && salt.value.trim()) args.salt = salt.value.trim();
  if (usesParameters.value && Object.keys(parameters.value).length > 0) {
    args.parameters = parameters.value;
  }
  return args;
});

interface DigestAnswer {
  kind: "digest";
  details: DigestDetails;
  text: string;
}
interface VerifyAnswer {
  kind: "verify";
  details: VerifyDetails;
  text: string;
}
interface ListAnswer {
  kind: "list";
  algorithms: AlgorithmInfo[];
  text: string;
}
interface DescribeAnswer {
  kind: "describe";
  info: AlgorithmInfo;
  text: string;
}
interface ErrorAnswer {
  kind: "error";
  name: string;
  message: string;
  text: string;
}
type Answer = DigestAnswer | VerifyAnswer | ListAnswer | DescribeAnswer | ErrorAnswer;

const current = computed(() => OPERATIONS.find((row) => row.key === operation.value)!);
const position = computed(() => OPERATIONS.findIndex((row) => row.key === operation.value) + 1);

/**
 * Runs the call through the executor the tool runs. Only a `HashError` is an answer; anything
 * else is a bug in the library and is rethrown.
 *
 * @param {Operation} op - Which tool.
 * @param {Record<string, unknown>} args - Its arguments.
 * @returns {Answer} What the response instrument shows.
 */
function run(op: Operation, args: Record<string, unknown>): Answer {
  const tool = OPERATIONS.find((row) => row.key === op)!.tool;
  try {
    if (op === "algorithms") {
      const result = hashAlgorithms(args);
      const text = result.content[0]!.text;
      return args.algorithm
        ? { kind: "describe", info: result.details.algorithms[0]!, text }
        : { kind: "list", algorithms: result.details.algorithms, text };
    }
    if (op === "verify") {
      const result = hashVerify(args as Parameters<typeof hashVerify>[0]);
      return { kind: "verify", details: result.details, text: result.content[0]!.text };
    }
    const result =
      op === "hmac"
        ? hashHmac(args as Parameters<typeof hashHmac>[0])
        : hashCompute(args as Parameters<typeof hashCompute>[0]);
    return { kind: "digest", details: result.details, text: result.content[0]!.text };
  } catch (error) {
    if (!(error instanceof HashError)) throw error;
    return {
      kind: "error",
      name: error.name,
      message: error.message,
      text: `${tool} failed: ${error.message}`,
    };
  }
}

/**
 * The answer follows the form a beat behind: a KDF at its real cost blocks the tab for a moment,
 * so it runs once typing stops, not on every key.
 */
const request = shallowRef({ op: operation.value, args: toolArgs.value });
let pending: ReturnType<typeof setTimeout> | undefined;
watch([operation, toolArgs], () => {
  clearTimeout(pending);
  pending = setTimeout(() => {
    request.value = { op: operation.value, args: toolArgs.value };
  }, 250);
});
onUnmounted(() => clearTimeout(pending));
const answer = computed(() => run(request.value.op, request.value.args));
const answered = computed(() => OPERATIONS.find((row) => row.key === request.value.op)!);
const answeredEntry = computed(
  () => algorithmEntry(String(request.value.args.algorithm ?? "")) ?? entry.value,
);

/** The same call as one CLI line. */
const cliLine = computed(() => {
  const args = toolArgs.value;
  if (operation.value === "algorithms") {
    if (describe.value) return `hashes info ${describe.value}`;
    const filters = [
      family.value ? `-f ${family.value}` : "",
      category.value ? `-c ${category.value}` : "",
    ].filter(Boolean);
    return ["hashes algorithms", ...filters].join(" ");
  }
  const flags = [
    inputEncoding.value !== "utf8" ? `--input-encoding ${inputEncoding.value}` : "",
    typeof args.keyEncoding === "string" ? `--key-encoding ${args.keyEncoding}` : "",
    encoding.value !== "hex" ? `-e ${encoding.value}` : "",
    optionFlags({
      ...(typeof args.salt === "string" ? { salt: args.salt } : {}),
      ...(usesParameters.value ? parameters.value : {}),
    }),
  ]
    .filter(Boolean)
    .join(" ");
  const head =
    operation.value === "hmac"
      ? `hashes hmac ${entry.value.slug} ${shellArg(input.value)} ${shellArg(key.value)}`
      : operation.value === "verify"
        ? `hashes verify ${entry.value.slug} ${shellArg(input.value)} ${shellArg(expected.value)}`
        : `hashes ${entry.value.slug} ${shellArg(input.value)}`;
  return flags ? `${head} ${flags}` : head;
});

/** The same call as a tool invocation, the JSON an MCP client sends. */
const toolCall = computed(() =>
  JSON.stringify({ name: current.value.tool, arguments: toolArgs.value }, null, 2),
);

/** The call in short form for the response bar. */
const call = computed(() => {
  const args = request.value.args;
  if (request.value.op === "algorithms") {
    const target = args.algorithm ?? args.family ?? args.category;
    return `${answered.value.tool}(${target ? `"${String(target)}"` : ""})`;
  }
  return `${answered.value.tool}("${String(args.algorithm)}", "${String(args.input)}")`;
});
const responseTitle = computed(
  () => `${answered.value.tool}(${JSON.stringify(request.value.args)})`,
);

/** The input's length as the executor read it: characters of text, or the bytes hex and base64 spell. */
const inputSize = computed(() => {
  const args = request.value.args;
  const text = String(args.input ?? "");
  if (args.inputEncoding === "hex") return `${Math.floor(text.trim().length / 2)} bytes · hex`;
  if (args.inputEncoding === "base64") return `base64 · ${text.trim().length} chars`;
  return `${new TextEncoder().encode(text).length} bytes · utf8`;
});

/**
 * What a digest depends on besides its encoding, as the tool's second line names it.
 *
 * @param {Record<string, unknown>} options - `details.options`.
 * @returns {string} `iterations 1000, salt 73616c74`, or empty.
 */
function parameterLine(options: Record<string, unknown>): string {
  return Object.entries(options)
    .filter(([name]) => name !== "encoding" && name !== "hmac")
    .map(([name, value]) => `${name} ${String(value)}`)
    .join(", ");
}

/** The cursor and the scan run once per answer, not once per keystroke that changes nothing. */
const scan = ref(0);
watch(
  () => answer.value.text,
  () => {
    scan.value += 1;
  },
);

/**
 * Picks an algorithm and fills its fields: a KDF gets a fixed salt and a small cost, so the first
 * answer doesn't spend seconds on 600000 PBKDF2 rounds.
 *
 * @param {string} slug - A built-in key.
 */
function selectAlgorithm(slug: string) {
  algorithmName.value = slug;
  for (const name of Object.keys(values)) delete values[name];
  salt.value = "";
  const sample = SAMPLE_OPTIONS[slug as keyof typeof SAMPLE_OPTIONS] ?? {};
  for (const [name, value] of Object.entries(sample)) {
    if (name === "salt") salt.value = String(value);
    else values[name] = String(value);
  }
}

/**
 * A chip: the algorithm with the sample input, and for verify the digest it should match.
 *
 * @param {string} slug - A built-in key.
 */
function loadSample(slug: string) {
  selectAlgorithm(slug);
  if (operation.value === "algorithms") operation.value = "hash";
  if (operation.value === "hmac" && !entry.value.info.hmac) operation.value = "hash";
  input.value = "hello world";
  inputEncoding.value = "utf8";
  if (operation.value === "verify") {
    const args = Object.entries(toolArgs.value).filter(([name]) => name !== "expected");
    const digest = run("hash", Object.fromEntries(args));
    if (digest.kind === "digest") expected.value = digest.details.digest;
  }
}

/** An HMAC needs an algorithm that has one; switching to it moves off one that doesn't. */
watch(operation, (op) => {
  if (op === "hmac" && !entry.value.info.hmac) selectAlgorithm("sha256");
});

const { copied, copy } = useCopied();

/** Query in, state out. Only values the form knows are read, the rest of the query is ignored. */
function readQuery(query: Record<string, unknown>) {
  const op = String(query.op ?? "");
  if (OPERATIONS.some((row) => row.key === op)) operation.value = op as Operation;
  const name = String(query.algorithm ?? "");
  const known = algorithmEntry(name);
  if (known && op !== "algorithms") {
    selectAlgorithm(name);
    for (const field of ownOptions(known.info)) {
      const value = query[field.name];
      if (typeof value !== "string") continue;
      if (field.name === "salt") salt.value = value;
      else values[field.name] = value;
    }
  }
  if (op === "algorithms" && known) describe.value = name;
  if (typeof query.family === "string") {
    const typed = query.family.toLowerCase();
    family.value = FAMILIES.find((name) => name.toLowerCase() === typed) ?? "";
  }
  if (typeof query.category === "string" && (hashCategories as readonly string[]).includes(query.category)) {
    category.value = query.category as HashCategory;
  }
  if (typeof query.input === "string") input.value = query.input;
  if (typeof query.key === "string") key.value = query.key;
  if (typeof query.expected === "string") expected.value = query.expected;
  const inEncoding = String(query.inputEncoding ?? "");
  if ((INPUT_ENCODINGS as readonly string[]).includes(inEncoding)) {
    inputEncoding.value = inEncoding as (typeof INPUT_ENCODINGS)[number];
  }
  const keyEncodingValue = String(query.keyEncoding ?? "");
  if ((INPUT_ENCODINGS as readonly string[]).includes(keyEncodingValue)) {
    keyEncoding.value = keyEncodingValue as (typeof INPUT_ENCODINGS)[number];
  }
  const outEncoding = String(query.encoding ?? "");
  if ((TEXT_ENCODINGS as readonly string[]).includes(outEncoding)) {
    encoding.value = outEncoding as (typeof TEXT_ENCODINGS)[number];
  }
  request.value = { op: operation.value, args: toolArgs.value };
}

const shareQuery = computed(() => {
  const query: Record<string, string> = { op: operation.value };
  const args = toolArgs.value;
  for (const [name, value] of Object.entries(args)) {
    if (name === "parameters") {
      for (const [option, setting] of Object.entries(value as Record<string, unknown>)) {
        query[option] = String(setting);
      }
    } else {
      query[name] = String(value);
    }
  }
  return query;
});

/**
 * Deep link once after mount. A prerendered page hydrates with an empty `route.query` and Nuxt
 * restores the address only afterwards, so the first non-empty query is read once, whichever
 * comes first.
 */
function applyDeepLink() {
  const stop = watch(
    () => route.query,
    (query) => {
      readQuery(query as Record<string, unknown>);
      stop();
    },
    { once: true, flush: "post" },
  );
  if (Object.keys(route.query).length > 0) {
    stop();
    readQuery(route.query as Record<string, unknown>);
  }
}

onMounted(() => {
  applyDeepLink();
  watch(shareQuery, (query) => {
    void router.replace({ query });
  });
});

const shareLink = computed(() => {
  if (!import.meta.client) return "";
  const url = new URL(window.location.href);
  url.search = new URLSearchParams(shareQuery.value).toString();
  return url.toString();
});
</script>

<template>
  <div class="playground">
    <form class="tool-console console-wide" @submit.prevent>
      <span class="console-cross console-cross-tl" aria-hidden="true">+</span>
      <span class="console-cross console-cross-br" aria-hidden="true">+</span>
      <header class="console-bar">
        <span class="console-title"
          ><span class="console-tag">Call</span>{{ current.tool
          }}<span class="console-file"
            >{{ String(position).padStart(2, "0") }} / {{ OPERATIONS.length }}</span
          ></span
        >
        <span class="console-meta" aria-label="Supported hosts: MCP, Pi, OMP and the AI SDK"
          >MCP · Pi · OMP · AI SDK</span
        >
        <span class="console-mark" aria-hidden="true" />
      </header>
      <div class="console-ruler" aria-hidden="true"><span class="console-cursor" /></div>

      <div class="console-band playground-band-first playground-columns">
        <div class="playground-column">
          <p class="console-label console-rule-title">
            <span
              >Operation <span aria-hidden="true">[ {{ OPERATIONS.length }} ]</span></span
            >
            <span class="console-mark" aria-hidden="true" />
          </p>
          <div role="group" aria-label="Operation" class="playground-ops console-draw">
            <button
              v-for="(row, index) in OPERATIONS"
              :key="row.key"
              type="button"
              class="console-lead"
              :aria-pressed="operation === row.key"
              @click="operation = row.key"
            >
              <span class="console-tag">{{ row.label }}</span>
              <span>{{ row.tool }}</span>
              <span
                class="console-leader"
                aria-hidden="true"
                :style="{ animationDelay: `${index * 60}ms` }"
              />
            </button>
          </div>
          <p class="console-about playground-tool-about">{{ current.about }}</p>
        </div>

        <div class="playground-column">
          <p class="console-label console-rule-title">
            <span
              >Input <span aria-hidden="true">[ {{ Object.keys(toolArgs).length || "no" }} arguments ]</span></span
            >
            <span class="console-mark" aria-hidden="true" />
          </p>

          <div class="console-readout">
            <dl v-if="operation === 'algorithms'" class="console-readout-rows">
              <div>
                <dt><label for="playground-family">family</label></dt>
                <dd>
                  <USelectMenu
                    id="playground-family"
                    v-model="family"
                    :items="familyItems"
                    value-key="value"
                    variant="none"
                    :search-input="false"
                    :disabled="describe !== ''"
                    class="w-full"
                  />
                </dd>
              </div>
              <div>
                <dt><label for="playground-category">category</label></dt>
                <dd>
                  <USelectMenu
                    id="playground-category"
                    v-model="category"
                    :items="categoryItems"
                    value-key="value"
                    variant="none"
                    :search-input="false"
                    :disabled="describe !== ''"
                    class="w-full"
                  />
                </dd>
              </div>
              <div>
                <dt><label for="playground-describe">algorithm</label></dt>
                <dd>
                  <USelectMenu
                    id="playground-describe"
                    v-model="describe"
                    :items="describeItems"
                    value-key="value"
                    variant="none"
                    class="w-full"
                  />
                </dd>
              </div>
            </dl>
            <dl v-else class="console-readout-rows">
              <div>
                <dt><label for="playground-algorithm">algorithm</label></dt>
                <dd>
                  <USelectMenu
                    id="playground-algorithm"
                    :model-value="entry.slug"
                    :items="algorithmItems"
                    value-key="value"
                    variant="none"
                    :icon="entry.icon"
                    class="w-full"
                    @update:model-value="selectAlgorithm($event as string)"
                  />
                </dd>
              </div>
              <div>
                <dt><label for="playground-input">input</label></dt>
                <dd>
                  <UTextarea
                    id="playground-input"
                    v-model="input"
                    variant="none"
                    :rows="1"
                    autoresize
                    :maxrows="6"
                    spellcheck="false"
                    autocomplete="off"
                    class="w-full"
                  />
                </dd>
              </div>
              <div>
                <dt><label for="playground-input-encoding">inputEncoding</label></dt>
                <dd>
                  <USelectMenu
                    id="playground-input-encoding"
                    v-model="inputEncoding"
                    :items="inputEncodingItems"
                    value-key="value"
                    variant="none"
                    :search-input="false"
                    class="w-full"
                  />
                </dd>
              </div>
              <div v-if="operation === 'hmac'">
                <dt><label for="playground-key">key</label></dt>
                <dd>
                  <UInput
                    id="playground-key"
                    v-model="key"
                    variant="none"
                    spellcheck="false"
                    autocomplete="off"
                    class="w-full"
                  />
                </dd>
              </div>
              <div v-if="operation === 'hmac'">
                <dt><label for="playground-key-encoding">keyEncoding</label></dt>
                <dd>
                  <USelectMenu
                    id="playground-key-encoding"
                    v-model="keyEncoding"
                    :items="inputEncodingItems"
                    value-key="value"
                    variant="none"
                    :search-input="false"
                    class="w-full"
                  />
                </dd>
              </div>
              <div v-if="operation === 'verify'">
                <dt><label for="playground-expected">expected</label></dt>
                <dd>
                  <UInput
                    id="playground-expected"
                    v-model="expected"
                    variant="none"
                    placeholder="the digest you were given"
                    spellcheck="false"
                    autocomplete="off"
                    class="w-full"
                  />
                </dd>
              </div>
              <div>
                <dt><label for="playground-encoding">encoding</label></dt>
                <dd>
                  <USelectMenu
                    id="playground-encoding"
                    v-model="encoding"
                    :items="encodingItems"
                    value-key="value"
                    variant="none"
                    :search-input="false"
                    class="w-full"
                  />
                </dd>
              </div>
              <template v-if="usesParameters">
                <div v-if="takesSalt">
                  <dt>
                    <label for="playground-salt"
                      >salt<span v-if="operation === 'hash'" class="playground-optional">?</span></label
                    >
                  </dt>
                  <dd>
                    <UInput
                      id="playground-salt"
                      v-model="salt"
                      variant="none"
                      placeholder="hex, 32 random bytes when empty"
                      spellcheck="false"
                      autocomplete="off"
                      class="w-full"
                    />
                  </dd>
                </div>
                <div v-for="field in parameterFields" :key="field.name">
                  <dt>
                    <label :for="`playground-option-${field.name}`"
                      >{{ field.name
                      }}<span v-if="!field.required" class="playground-optional">?</span></label
                    >
                  </dt>
                  <dd>
                    <UInput
                      :id="`playground-option-${field.name}`"
                      v-model="values[field.name]"
                      variant="none"
                      :type="field.type === 'number' ? 'number' : 'text'"
                      :placeholder="field.default !== undefined && field.default !== '' ? `default ${field.default}` : field.description"
                      spellcheck="false"
                      autocomplete="off"
                      class="w-full"
                    />
                  </dd>
                </div>
              </template>
            </dl>
          </div>

          <div
            v-if="operation !== 'algorithms'"
            class="playground-chips"
            role="group"
            aria-label="Sample algorithms"
          >
            <UButton
              v-for="algorithm in ALGORITHMS.filter((row) => operation !== 'hmac' || row.info.hmac)"
              :key="algorithm.slug"
              :color="entry.slug === algorithm.slug ? 'primary' : 'neutral'"
              variant="chip"
              :icon="algorithm.icon"
              :label="algorithm.slug"
              :aria-pressed="entry.slug === algorithm.slug"
              @click="loadSample(algorithm.slug)"
            />
          </div>

          <p class="playground-note">
            <template v-if="operation === 'verify'"
              >A chip fills in the digest that matches. Change one character of it, or switch to
              base64 and lowercase it, and watch the verdict flip.</template
            >
            <template v-else-if="operation === 'algorithms'"
              >Pick an algorithm to see its options the way a model sees them before its first
              call.</template
            >
            <template v-else
              >A chip loads the algorithm with <code>hello world</code>. A KDF comes with a fixed
              salt and a small cost, so the first answer doesn't take seconds.</template
            >
          </p>
        </div>
      </div>

      <div class="console-band playground-columns">
        <div class="playground-column">
          <p class="console-label console-rule-title">
            <span>CLI <span aria-hidden="true">[ same call ]</span></span>
            <span class="console-mark" aria-hidden="true" />
            <UButton
              color="neutral"
              variant="subtle"
              :icon="copied === 'cli' ? 'i-lucide-check' : 'i-lucide-copy'"
              :label="copied === 'cli' ? 'copied' : 'copy'"
              :aria-label="copied === 'cli' ? 'Copied' : 'Copy the CLI line'"
              @click="copy('cli', cliLine)"
            />
          </p>
          <!-- prettier-ignore -->
          <pre class="console-snippet"><code><span class="playground-prompt">$ </span><span v-for="(token, index) in shellTokens(cliLine)" :key="index" :class="token.cls">{{ token.text }}</span></code></pre>
        </div>
        <div class="playground-column">
          <p class="console-label console-rule-title">
            <span>Tool <span aria-hidden="true">[ what an MCP client sends ]</span></span>
            <span class="console-mark" aria-hidden="true" />
            <UButton
              color="neutral"
              variant="subtle"
              :icon="copied === 'tool' ? 'i-lucide-check' : 'i-lucide-copy'"
              :label="copied === 'tool' ? 'copied' : 'copy'"
              :aria-label="copied === 'tool' ? 'Copied' : 'Copy the tool call'"
              @click="copy('tool', toolCall)"
            />
          </p>
          <!-- prettier-ignore -->
          <pre class="console-snippet"><code><span v-for="(token, index) in jsonTokens(toolCall)" :key="index" :class="token.cls">{{ token.text }}</span></code></pre>
        </div>
      </div>

      <footer class="console-footer console-footer-plain">
        <ul class="console-links">
          <li>
            <button type="button" @click="copy('link', shareLink)">
              <span aria-hidden="true">→ </span
              >{{ copied === "link" ? "permalink copied" : "copy the permalink" }}
            </button>
          </li>
        </ul>
        <span class="console-meta">every state is a link</span>
      </footer>
    </form>

    <!-- The call runs from the request down into the response, the way the zone's circuit runs into the request. -->
    <div class="playground-link" aria-hidden="true">
      <svg :key="scan" class="hero-circuit" viewBox="0 0 160 56">
        <path class="hero-circuit-rail" d="M80 0V16L96 32V56" />
        <path class="hero-circuit-live" d="M80 0V16L96 32V56" pathLength="1" />
        <path class="hero-circuit-seg" d="M96 38V48" />
        <rect class="hero-circuit-node" x="92.5" y="52.5" width="7" height="7" />
      </svg>
      <span class="hero-circuit-tag">answer</span>
    </div>

    <section class="tool-console console-wide" aria-live="polite">
      <span class="console-cross console-cross-tl" aria-hidden="true">+</span>
      <span class="console-cross console-cross-br" aria-hidden="true">+</span>
      <header class="console-bar">
        <UTooltip :text="responseTitle">
          <span class="console-title playground-call" tabindex="0"
            ><span class="console-tag">{{ answered.label }}</span>{{ call }}</span
          >
        </UTooltip>
        <span v-if="answer.kind === 'digest' || answer.kind === 'verify'" class="console-meta"
          >{{ answer.details.digestLength }} bytes · {{ answer.details.encoding }}</span
        >
        <span v-else-if="answer.kind === 'list'" class="console-meta"
          >{{ answer.algorithms.length }} algorithms · listing order</span
        >
        <span v-else-if="answer.kind === 'describe'" class="console-meta"
          >{{ answer.info.family }} · {{ digestBits(answer.info) }}</span
        >
        <span v-else class="console-meta">{{ answer.name }}</span>
        <span class="console-mark" aria-hidden="true" />
      </header>
      <div class="console-ruler" aria-hidden="true">
        <span :key="scan" class="console-cursor" />
      </div>

      <template v-if="answer.kind === 'digest'">
        <div class="console-band console-subject-band">
          <div :key="scan" class="console-scan" aria-hidden="true" />
          <div class="console-identity-block">
            <ConsoleReticle :key="answeredEntry.slug" :icon="answeredEntry.icon" />
            <div class="console-name">
              <span class="console-label"
                >{{ answer.details.operation === "hmac" ? "HMAC" : "Digest" }} /
                <span class="console-label-key">{{ answeredEntry.slug }}</span></span
              >
              <h3>{{ answeredEntry.info.label }}</h3>
              <p class="console-about">{{ answeredEntry.blurb }}.</p>
            </div>
          </div>
          <div class="console-readout">
            <svg class="console-link" viewBox="0 0 32 40" fill="none" aria-hidden="true">
              <circle cx="3" cy="12" r="2.5" />
              <path d="M5.5 12H14L22 20H32" />
            </svg>
            <dl :key="scan" class="console-readout-rows console-animate">
              <div>
                <dt>Length</dt>
                <dd class="console-accent">
                  {{ answer.details.digestLength }} bytes · {{ answer.details.digestLength * 8 }}-bit
                </dd>
              </div>
              <div>
                <dt>Input</dt>
                <dd>{{ inputSize }}</dd>
              </div>
              <div>
                <dt>Encoding</dt>
                <dd>{{ answer.details.encoding }}</dd>
              </div>
              <div>
                <dt>Depends on</dt>
                <dd>
                  <UTooltip
                    v-if="parameterLine(answer.details.options)"
                    :text="parameterLine(answer.details.options)"
                  >
                    <span class="playground-line" tabindex="0">{{
                      parameterLine(answer.details.options)
                    }}</span>
                  </UTooltip>
                  <span v-else class="playground-none">the input alone</span>
                </dd>
              </div>
            </dl>
          </div>
        </div>
        <div class="console-band">
          <p class="console-label console-rule-title">
            <span>Digest <span aria-hidden="true">[ content[0].text, first line ]</span></span>
            <span class="console-mark" aria-hidden="true" />
            <UButton
              color="neutral"
              variant="subtle"
              :icon="copied === 'out' ? 'i-lucide-check' : 'i-lucide-copy'"
              :label="copied === 'out' ? 'copied' : 'copy'"
              :aria-label="copied === 'out' ? 'Copied' : 'Copy the digest'"
              @click="copy('out', answer.details.digest)"
            />
          </p>
          <pre :key="scan" class="console-snippet playground-output"><code>{{ answer.details.digest }}</code></pre>
        </div>
      </template>

      <template v-else-if="answer.kind === 'verify'">
        <div class="console-band console-subject-band">
          <div :key="scan" class="console-scan" aria-hidden="true" />
          <div class="console-identity-block">
            <ConsoleReticle :key="answeredEntry.slug" icon="i-lucide-check-check" />
            <div class="console-name">
              <span class="console-label"
                >Verdict / <span class="console-label-key">{{ answeredEntry.slug }}</span></span
              >
              <h3
                class="console-name-mono"
                :class="answer.details.match ? 'playground-valid' : 'playground-invalid'"
              >
                {{ answer.details.match ? "MATCH" : "MISMATCH" }}
              </h3>
              <p class="console-about">
                <template v-if="answer.details.match"
                  >Every byte of the expected digest equals the one computed here.</template
                >
                <template v-else
                  >The expected digest names other bytes, or isn't valid
                  {{ answer.details.encoding }} at all.</template
                >
              </p>
            </div>
          </div>
          <div class="console-readout">
            <svg class="console-link" viewBox="0 0 32 40" fill="none" aria-hidden="true">
              <circle cx="3" cy="12" r="2.5" />
              <path d="M5.5 12H14L22 20H32" />
            </svg>
            <dl :key="scan" class="console-readout-rows console-animate">
              <div>
                <dt>Expected</dt>
                <dd>
                  <UTooltip :text="answer.details.expected">
                    <span class="playground-line" tabindex="0">{{ answer.details.expected }}</span>
                  </UTooltip>
                </dd>
              </div>
              <div>
                <dt>Actual</dt>
                <dd :class="{ 'console-accent': answer.details.match }">
                  <UTooltip :text="answer.details.digest">
                    <span class="playground-line" tabindex="0">{{ answer.details.digest }}</span>
                  </UTooltip>
                </dd>
              </div>
              <div>
                <dt>Encoding</dt>
                <dd>{{ answer.details.encoding }}</dd>
              </div>
              <div>
                <dt>Input</dt>
                <dd>{{ inputSize }}</dd>
              </div>
            </dl>
          </div>
        </div>
      </template>

      <ol
        v-else-if="answer.kind === 'list'"
        :key="scan"
        class="console-rows console-animate playground-list"
      >
        <li
          v-for="(info, index) in answer.algorithms"
          :key="info.name"
          :style="{ animationDelay: `${Math.min(index * 30, 600)}ms` }"
        >
          <NuxtLink :to="`/algorithms/${info.name}`" class="playground-list-name">{{ info.name }}</NuxtLink>
          <span class="playground-none">{{ info.family }}</span>
          <span>{{ digestBits(info) }}</span>
          <span :class="info.hmac ? 'playground-valid' : 'playground-none'">{{
            info.hmac ? "HMAC" : "no HMAC"
          }}</span>
        </li>
      </ol>

      <template v-else-if="answer.kind === 'describe'">
        <div class="console-band console-subject-band">
          <div :key="scan" class="console-scan" aria-hidden="true" />
          <div class="console-identity-block">
            <ConsoleReticle :key="answeredEntry.slug" :icon="answeredEntry.icon" />
            <div class="console-name">
              <span class="console-label">Hash / {{ categoryLabel(answer.info.category) }}</span>
              <h3>{{ answer.info.label }}</h3>
              <p class="console-about">{{ answer.info.description }}</p>
            </div>
          </div>
          <div class="console-readout">
            <svg class="console-link" viewBox="0 0 32 40" fill="none" aria-hidden="true">
              <circle cx="3" cy="12" r="2.5" />
              <path d="M5.5 12H14L22 20H32" />
            </svg>
            <dl :key="scan" class="console-readout-rows console-animate">
              <div>
                <dt>Digest</dt>
                <dd class="console-accent">{{ digestBits(answer.info) }}</dd>
              </div>
              <div>
                <dt>HMAC</dt>
                <dd>{{ answer.info.hmac ? "takes a key" : "no key mode" }}</dd>
              </div>
              <div>
                <dt>Options</dt>
                <dd>{{ answer.info.options.length }}</dd>
              </div>
            </dl>
          </div>
        </div>
        <ol :key="scan" class="console-rows console-animate playground-options">
          <li v-for="option in answer.info.options" :key="option.name">
            <code>{{ option.name }}</code>
            <span :class="option.required ? 'playground-valid' : 'playground-none'">{{
              option.required
                ? "required"
                : option.default === undefined || option.default === ""
                  ? "optional"
                  : `default ${option.default}`
            }}</span>
            <span class="playground-option-about">{{ option.description }}</span>
          </li>
        </ol>
      </template>

      <div v-else class="console-band console-subject-band">
        <div :key="scan" class="console-scan" aria-hidden="true" />
        <div class="console-identity-block">
          <ConsoleReticle :key="answer.name" icon="i-lucide-circle-alert" />
          <div class="console-name">
            <span class="console-label">Error / thrown</span>
            <h3 class="console-name-mono playground-invalid">{{ answer.name }}</h3>
            <p class="console-about">{{ answer.message }}</p>
          </div>
        </div>
        <div class="console-readout">
          <dl class="console-readout-rows">
            <div>
              <dt>Tool</dt>
              <dd>{{ answered.tool }}</dd>
            </div>
            <div>
              <dt>Takes</dt>
              <dd>
                <span class="playground-line">{{
                  answeredEntry.info.options.map((field) => field.name + (field.required ? "" : "?")).join(", ")
                }}</span>
              </dd>
            </div>
          </dl>
        </div>
      </div>

      <ConsoleResponse :title="responseTitle" :text="answer.text" />

      <footer class="console-footer console-footer-plain">
        <ul class="console-links">
          <li v-if="answer.kind !== 'list'">
            <NuxtLink :to="answeredEntry.to"
              ><span aria-hidden="true">→ </span>{{ answeredEntry.info.label }}</NuxtLink
            >
          </li>
          <li>
            <NuxtLink
              :to="
                answered.key === 'verify' || answered.key === 'hmac'
                  ? '/guide/verify'
                  : answeredEntry.info.category === 'password'
                    ? '/guide/kdf'
                    : '/guide/hashing'
              "
              ><span aria-hidden="true">→ </span>How it works</NuxtLink
            >
          </li>
        </ul>
        <span class="console-meta">in your browser / no network</span>
      </footer>
    </section>
  </div>
</template>

<style scoped>
.playground {
  display: grid;
  grid-template-columns: minmax(0, 1fr);
  gap: 0;
}
/* The link between the two instruments: the zone's circuit, standing on its own 56 px of height. */
.playground-link {
  position: relative;
  height: 56px;
}
.playground-link > .hero-circuit {
  bottom: 0;
}
.playground-link > .hero-circuit-tag {
  bottom: 18px;
}
/* One track by default: an implicit auto track would grow to the widest chip row and push the page sideways. */
.playground-columns {
  display: grid;
  grid-template-columns: minmax(0, 1fr);
  gap: 24px 48px;
}
.playground-column {
  min-width: 0;
}
@media (width >= 56rem) {
  .playground-columns {
    grid-template-columns: minmax(0, 1fr) minmax(0, 1fr);
  }
}
@media (width >= 80rem) {
  .playground-ops {
    grid-template-columns: repeat(2, minmax(0, 1fr));
  }
}
/* The playground carries more rows than a dossier, so its bands breathe a little wider. */
.playground .console-bar {
  padding-block: 12px;
}
.playground .console-band {
  padding: 22px 24px 24px;
}
.playground .console-rule-title {
  margin-bottom: 18px;
}
.playground .console-readout-rows > div {
  padding: 12px 16px;
}
.playground-prompt {
  color: var(--ui-text-dimmed);
}
.playground .console-snippet {
  padding: 12px 16px;
  line-height: 1.8;
  overflow-wrap: anywhere;
}
.playground .console-footer {
  padding: 14px 24px;
}
.playground .console-rows li {
  padding: 12px 24px;
}
.playground-band-first {
  border-top: 0;
}
.playground-tool-about {
  margin-top: 20px;
  font-size: 14px;
}
.playground-ops {
  display: grid;
  gap: 0 40px;
  margin-top: -12px;
}
.playground-ops .console-lead {
  margin-top: 12px;
  padding: 2px 0;
}
.playground-ops .console-lead > span:not(.console-tag, .console-leader) {
  white-space: nowrap;
  color: var(--ui-text-muted);
}
.playground-ops .console-lead[aria-pressed="true"] > span:not(.console-tag, .console-leader),
.playground-ops .console-lead:hover > span:not(.console-tag, .console-leader) {
  color: var(--ui-text-highlighted);
}
.playground-optional {
  color: var(--ui-text-dimmed);
}
.playground-checks {
  display: flex;
  flex-wrap: wrap;
  gap: 6px 18px;
}
.playground-chips {
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
  margin-top: 18px;
}
.playground-note {
  margin: 16px 0 0;
  font-family: var(--font-sans);
  font-size: 14px;
  line-height: 1.7;
  color: var(--ui-text-muted);
}
.playground-call {
  min-width: 0;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.playground-none {
  color: var(--ui-text-dimmed);
}
.playground-valid {
  color: var(--console-accent);
}
.playground-invalid {
  color: var(--hashes-del);
}
.playground-line {
  display: block;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}
/* The digest as a value, whole and wrapped: 128 hex digits never scroll the page. */
.playground-output {
  max-height: 16rem;
  overflow-y: auto;
  white-space: pre-wrap;
  color: var(--ui-text-highlighted);
}
/* One row per algorithm of the listing: the name as a link, family, size, HMAC. */
.playground-list li {
  grid-template-columns: minmax(0, 12rem) minmax(0, 10rem) 6rem minmax(0, 1fr);
}
.playground-list-name {
  color: var(--ui-text-highlighted);
}
.playground-list-name:hover {
  color: var(--console-accent);
}
/* One row per option of `hash_algorithms` with a name: the name, whether it is required, what it does. */
.playground-options li {
  grid-template-columns: 9rem 8rem minmax(0, 1fr);
}
.playground-options code {
  font-family: var(--font-mono);
  color: var(--ui-text-highlighted);
}
.playground-option-about {
  font-family: var(--font-sans);
  font-size: 14px;
  color: var(--ui-text-muted);
}
@media (width < 640px) {
  .playground-options li {
    grid-template-columns: minmax(0, 1fr) auto;
  }
  .playground-option-about {
    grid-column: 1 / -1;
  }
  .playground-list li {
    grid-template-columns: minmax(0, 1fr) auto;
  }
  .playground-list li > span:nth-of-type(1) {
    display: none;
  }
}
@media (width < 400px) {
  /* The label column fits the longest label, `inputEncoding`, with room to spare. */
  .playground .console-readout-rows > div {
    grid-template-columns: 6.25rem minmax(0, 1fr);
    gap: 8px;
    padding: 10px 12px;
  }
  .playground .console-band,
  .playground .console-footer,
  .playground .console-rows li {
    padding-inline: 14px;
  }
}
</style>
