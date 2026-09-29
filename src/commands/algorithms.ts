import { defineCommand } from "citty";
import { algorithmInfos } from "../core/resolve.ts";
import { hashCategories } from "../index.ts";

export default defineCommand({
  meta: { name: "algorithms", description: "List all registered algorithms" },
  args: {
    family: {
      type: "string",
      description: "Filter by family, such as SHA, BLAKE or CRC",
      alias: "f",
    },
    category: {
      type: "string",
      description: `Filter by category: ${hashCategories.join(", ")}`,
      alias: "c",
    },
  },
  run({ args }) {
    const rows = algorithmInfos({ category: args.category, family: args.family }).map((info) => ({
      name: info.name,
      family: info.family,
      category: info.category,
      digest: info.digestLength === undefined ? "variable" : `${info.digestLength * 8}-bit`,
      hmac: info.hmac ? "yes" : "no",
      label: info.label,
    }));
    const width = {
      name: Math.max(4, ...rows.map((row) => row.name.length)),
      family: Math.max(6, ...rows.map((row) => row.family.length)),
      category: Math.max(8, ...rows.map((row) => row.category.length)),
      digest: Math.max(6, ...rows.map((row) => row.digest.length)),
    };
    const line = (row: Readonly<Record<keyof typeof width | "hmac" | "label", string>>): string =>
      `${row.name.padEnd(width.name)}  ${row.family.padEnd(width.family)}  ${row.category.padEnd(width.category)}  ${row.digest.padEnd(width.digest)}  ${row.hmac.padEnd(4)}  ${row.label}`;
    const header = line({
      name: "Name",
      family: "Family",
      category: "Category",
      digest: "Digest",
      hmac: "HMAC",
      label: "Label",
    });
    process.stdout.write(`${[header, ...rows.map(line)].join("\n")}\n`);
  },
});
