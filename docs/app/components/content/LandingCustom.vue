<script setup lang="ts">
import { tokens } from "../../utils/tokens";

const { copied, copy } = useCopied();

/** A digest of your own, the shape every fixed-length built-in has: a static key, about, digest. */
const FILE = [
  'import { FixedHash, create, register } from "@agntn/hashes";',
  "",
  "class Fnv1a32 extends FixedHash {",
  '  static readonly key = "fnv1a-32";',
  "  protected readonly about = {",
  '    label: "FNV-1a (32-bit)",',
  '    description: "FNV-1a 32-bit, for hash tables",',
  '    family: "non-cryptographic",',
  "    digestLength: 4,",
  "  } as const;",
  "",
  "  protected digest(bytes: Uint8Array): Uint8Array {",
  "    let hash = 0x811c9dc5;",
  "    for (const byte of bytes) hash = Math.imul(hash ^ byte, 0x01000193);",
  "    const out = new Uint8Array(4);",
  "    new DataView(out.buffer).setUint32(0, hash >>> 0);",
  "    return out;",
  "  }",
  "}",
  "",
  "register(Fnv1a32);",
  'create("fnv1a-32").hash("a").digest; // "e40c292c"',
] as const;

/**
 * What the panel shows: the method the section is about in full, `about` folded the way an editor
 * folds it. Copy hands out `FILE`, every line.
 */
const LINES = [
  ...FILE.slice(0, 4),
  "  protected readonly about = { /* label, family, digestLength */ };",
  ...FILE.slice(10),
] as const;
</script>

<template>
  <section class="tool-console landing-custom" aria-label="An algorithm of your own">
    <span class="console-cross console-cross-tl" aria-hidden="true">+</span>
    <span class="console-cross console-cross-br" aria-hidden="true">+</span>

    <header class="console-bar">
      <span class="console-title"><span class="console-tag">File</span>fnv1a-32.ts</span>
      <span class="console-meta">folded · copy is whole</span>
      <span class="console-mark" aria-hidden="true" />
      <UButton
        color="neutral"
        variant="subtle"
        :icon="copied === 'fnv' ? 'i-lucide-check' : 'i-lucide-copy'"
        :label="copied === 'fnv' ? 'copied' : 'copy'"
        :aria-label="copied === 'fnv' ? 'Copied' : 'Copy fnv1a-32.ts'"
        @click="copy('fnv', FILE.join('\n'))"
      />
    </header>
    <div class="console-ruler" aria-hidden="true" />

    <div class="custom-body">
      <!-- prettier-ignore -->
      <pre class="console-snippet console-lines"><code><span v-for="(line, index) in LINES" :key="index"><span v-for="(token, part) in tokens(line)" :key="part" :class="token.cls">{{ token.text }}</span></span></code></pre>
    </div>
  </section>
</template>

<style scoped>
.custom-body {
  padding: 14px 20px 18px;
}
/* Breaks only between words: a string split at any character is hard to read. */
.custom-body > .console-snippet {
  overflow-wrap: break-word;
}
@media (width < 400px) {
  .custom-body {
    padding-inline: 14px;
  }
}
</style>
