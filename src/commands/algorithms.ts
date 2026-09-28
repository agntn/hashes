import { defineCommand } from "citty";
import { algorithmInfos } from "../core/resolve.ts";
import { hashFamilies } from "../index.ts";

export default defineCommand({
  meta: { name: "algorithms", description: "List all registered algorithms" },
  args: {
    family: {
      type: "string",
      description: `Filter by family: ${hashFamilies.join(", ")}`,
      alias: "f",
    },
  },
  run({ args }) {
    const rows = algorithmInfos(args.family).map((info) => ({
      name: info.name,
      family: info.family,
      digest: info.digestLength === undefined ? "variable" : `${info.digestLength * 8}-bit`,
      hmac: info.hmac ? "yes" : "no",
      label: info.label,
    }));
    const width = {
      name: Math.max(4, ...rows.map((row) => row.name.length)),
      family: Math.max(6, ...rows.map((row) => row.family.length)),
      digest: Math.max(6, ...rows.map((row) => row.digest.length)),
    };
    const line = (row: Readonly<Record<keyof typeof width | "hmac" | "label", string>>): string =>
      `${row.name.padEnd(width.name)}  ${row.family.padEnd(width.family)}  ${row.digest.padEnd(width.digest)}  ${row.hmac.padEnd(4)}  ${row.label}`;
    const header = line({
      name: "Name",
      family: "Family",
      digest: "Digest",
      hmac: "HMAC",
      label: "Label",
    });
    process.stdout.write(`${[header, ...rows.map(line)].join("\n")}\n`);
  },
});
