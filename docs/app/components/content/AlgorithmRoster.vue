<script setup lang="ts">
import type { TableColumn } from "@nuxt/ui";
import type { HashFamily } from "@agntn/hashes";
import {
  ALGORITHMS,
  digestBits,
  familyLabel,
  ownOptions,
  securityParts,
  type AlgorithmEntry,
} from "../../utils/algorithms";
import { ROSTER_CLASS, ROSTER_TABLE_UI } from "../../utils/roster";

interface Row {
  readonly entry: AlgorithmEntry;
  readonly slug: string;
  readonly label: string;
  readonly family: string;
  /** Digest bits for sorting; a KDF, where the caller picks the length, sorts last. */
  readonly bits: number;
  readonly hmac: string;
  readonly required: readonly string[];
  readonly optional: readonly string[];
  readonly security: { short: string; full: string } | undefined;
}

/** One family only, the way `hashes algorithms -f` lists it; every algorithm when left out. */
const props = defineProps<{ family?: HashFamily }>();

/** Every value comes from `info()`; the listing order is the default. */
const rows = computed<Row[]>(() =>
  ALGORITHMS.filter((entry) => props.family === undefined || entry.info.family === props.family).map(
    (entry) => ({
      entry,
      slug: entry.slug,
      label: entry.info.label,
      family: familyLabel(entry.info.family),
      bits: entry.info.digestLength === undefined ? Number.MAX_SAFE_INTEGER : entry.info.digestLength * 8,
      hmac: entry.info.hmac ? "yes" : "no",
      required: ownOptions(entry.info).filter((option) => option.required).map((option) => option.name),
      optional: ownOptions(entry.info).filter((option) => !option.required).map((option) => option.name),
      security: securityParts(entry.info),
    }),
  ),
);

const sorting = ref<{ id: string; desc: boolean }[]>([]);

const roster = useTemplateRef<HTMLElement>("roster");
useRosterFlip(
  () => roster.value,
  () => sorting.value,
);

const allColumns: TableColumn<Row>[] = [
  { accessorKey: "label", header: "Algorithm", sortingFn: "text", meta: { class: { th: "w-[15rem]" } } },
  {
    accessorKey: "family",
    header: "Family",
    sortingFn: "text",
    meta: { class: { th: "w-[8.5rem]", td: "@max-[52rem]/roster:justify-self-end" } },
  },
  {
    accessorKey: "bits",
    header: "Digest",
    sortingFn: "basic",
    meta: { class: { th: "w-[5.5rem]" } },
  },
  {
    accessorKey: "hmac",
    header: "HMAC",
    sortingFn: "text",
    meta: { class: { th: "w-[4.5rem]" } },
  },
  {
    id: "options",
    header: "Options",
    enableSorting: false,
    meta: { class: { td: "min-w-0" } },
  },
  {
    id: "security",
    header: "Security",
    enableSorting: false,
    meta: { class: { th: "w-[13rem]" } },
  },
];

/** A roster of one family drops the column that would say the same word on every row. */
const columns = computed(() =>
  allColumns.filter(
    (column) => !(props.family && "accessorKey" in column && column.accessorKey === "family"),
  ),
);

const order = computed(() => {
  const [first] = sorting.value;
  if (first === undefined) return "listing order";
  const label = allColumns.find(
    (column) => "accessorKey" in column && column.accessorKey === first.id,
  )?.header;
  return `by ${String(label).toLowerCase()} ${first.desc ? "descending" : "ascending"}`;
});
</script>

<template>
  <section ref="roster" class="roster not-prose my-6" aria-label="Algorithms">
    <span class="console-cross console-cross-tl" aria-hidden="true">+</span>
    <span class="console-cross console-cross-br" aria-hidden="true">+</span>
    <header :class="ROSTER_CLASS.bar">
      <span :class="ROSTER_CLASS.title">{{
        family ? `hashes algorithms -f ${family}` : "algorithms()"
      }}</span>
      <span :class="ROSTER_CLASS.meta">{{ rows.length }} {{ rows.length === 1 ? "algorithm" : "algorithms" }} · {{ order }}</span>
    </header>
    <div class="roster-ruler" aria-hidden="true" />
    <UTable
      v-model:sorting="sorting"
      :data="rows"
      :columns="columns"
      :get-row-id="(row) => row.slug"
      :ui="ROSTER_TABLE_UI"
    >
      <template #label-header="{ column }"><RosterSort :column="column" label="Algorithm" /></template>
      <template #family-header="{ column }"><RosterSort :column="column" label="Family" /></template>
      <template #bits-header="{ column }"><RosterSort :column="column" label="Digest" /></template>
      <template #hmac-header="{ column }"><RosterSort :column="column" label="HMAC" /></template>
      <template #label-cell="{ row }">
        <NuxtLink :to="row.original.entry.to" :class="[ROSTER_CLASS.name, 'max-w-full items-baseline']">
          <UIcon
            :name="row.original.entry.icon"
            class="relative top-0.5 size-3.5 flex-none"
            aria-hidden="true"
          />
          <span class="truncate">{{ row.original.label }}</span>
          <span :class="[ROSTER_CLASS.id, 'flex-none']">{{ row.original.slug }}</span>
        </NuxtLink>
      </template>
      <template #family-cell="{ row }">
        <span class="whitespace-nowrap text-muted">{{ row.original.family }}</span>
      </template>
      <template #bits-cell="{ row }">
        <span class="whitespace-nowrap text-highlighted">{{ digestBits(row.original.entry.info) }}</span>
      </template>
      <template #hmac-cell="{ row }">
        <span :class="row.original.hmac === 'yes' ? 'text-highlighted' : 'text-dimmed'"
          ><span class="@min-[52rem]/roster:hidden">HMAC </span>{{ row.original.hmac }}</span
        >
      </template>
      <template #options-cell="{ row }">
        <span v-if="row.original.required.length || row.original.optional.length" class="text-muted"
          ><template v-for="(name, index) in row.original.required" :key="name"
            ><span class="text-highlighted">{{ name }}</span
            ><template v-if="index < row.original.required.length - 1 || row.original.optional.length"
              >,
            </template></template
          ><template v-for="(name, index) in row.original.optional" :key="name"
            >{{ name }}<span class="text-dimmed">?</span
            ><template v-if="index < row.original.optional.length - 1">, </template></template
          ></span
        >
        <span v-else class="text-dimmed">no options</span>
      </template>
      <template #security-cell="{ row }">
        <span :class="ROSTER_CLASS.count"
          ><span :class="ROSTER_CLASS.leader" aria-hidden="true" /><UTooltip
            v-if="row.original.security"
            :text="row.original.security.full"
            ><span class="min-w-0 truncate text-highlighted" tabindex="0">{{
              row.original.security.short
            }}</span></UTooltip
          ><span v-else class="whitespace-nowrap">not stated</span></span
        >
      </template>
    </UTable>
    <footer :class="ROSTER_CLASS.footer">
      <span>read from the registry in your browser / no network</span>
      <span :class="ROSTER_CLASS.meta">a name with ? is optional</span>
    </footer>
  </section>
</template>
