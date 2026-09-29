import { defineCommand } from "citty";
import { resolveAlgorithm } from "../index.ts";

export default defineCommand({
  meta: { name: "info", description: "Show algorithm details" },
  args: {
    algorithm: { type: "positional", description: "Algorithm name", required: true },
  },
  run({ args }) {
    const info = resolveAlgorithm(args.algorithm).info();
    const lines = [
      `${info.label} (${info.name})`,
      info.description,
      "",
      `Family:    ${info.family}`,
      `Category:  ${info.category}`,
    ];
    if (info.digestLength !== undefined) {
      lines.push(`Digest:    ${info.digestLength * 8}-bit (${info.digestLength} bytes)`);
    }
    lines.push(`HMAC:      ${info.hmac ? "supported" : "not supported"}`);
    if (info.dependency) lines.push(`Requires:  ${info.dependency}`);
    if (info.securityNote) lines.push(`Security:  ${info.securityNote}`);
    lines.push("", "Options:");
    for (const option of info.options) {
      const fallback = option.default === undefined ? "" : ` (default: ${String(option.default)})`;
      lines.push(
        `  --${option.name}${option.required ? " [required]" : ""}${fallback}: ${option.description}`,
      );
    }
    process.stdout.write(`${lines.join("\n")}\n`);
  },
});
