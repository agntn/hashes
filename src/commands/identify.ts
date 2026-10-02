import { defineCommand } from "citty";
import { identifyDigest, identityText } from "../core/identify.ts";

export default defineCommand({
  meta: {
    name: "identify",
    description: "Guess which algorithms a hash may come from, by its prefix or its length",
  },
  args: {
    digest: {
      type: "positional",
      description: "The hash: hex, base64, or a string such as $2b$... (quote it in the shell)",
      required: true,
    },
  },
  run({ args }) {
    const { heading, lines } = identityText(identifyDigest(args.digest));
    process.stderr.write(`${heading}\n`);
    for (const line of lines) process.stdout.write(`${line}\n`);
    if (lines.length === 0) process.exitCode = 1;
  },
});
