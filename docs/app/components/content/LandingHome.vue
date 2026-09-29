<script setup lang="ts">
import { SAMPLE_INPUT } from "../../composables/useLandingHash";
import { ALGORITHMS, FAMILIES, HMAC_COUNT, categorySize } from "../../utils/algorithms";
import { spellOut, spellOutCapital } from "../../utils/format";
import { TOOLS } from "../../utils/tools";

const { samples, paused, current, step } = useLandingHash();
</script>

<template>
  <div class="hashes-landing not-prose">
    <LandingHero :sample="current" :samples="samples" @step="step" @pause="paused = $event" />

    <LandingFeature
      title="Same call, every algorithm"
      to="/guide/hashing"
      link="Hashing"
      :checks="[
        'create(name) wants the exact key. resolveAlgorithm forgives case, spaces and underscores',
        'Every result is { digest, algorithm, operation, encoding, digestLength, options }',
        'Hex, base64, base64url or raw bytes. Text is UTF-8, a Uint8Array is hashed as it is',
      ]"
    >
      <code class="hashes-code">create("sha256")</code> gives you an object with one method that
      matters, <code class="hashes-code">hash</code>. Pass a key and it's an HMAC, pass an encoding
      and the digest comes back in it. This file walks through {{ samples.length }} algorithms and
      none of it is a recording. Your browser computes every line, with the same TypeScript the
      package ships.
      <template #visual>
        <LandingRotatingCode :sample="current" @step="step" @pause="paused = $event" />
      </template>
    </LandingFeature>

    <LandingFeature
      title="Verify compares bytes, not letters"
      to="/guide/verify"
      link="HMAC and verify"
      :checks="[
        'digestMatches decodes both sides and compares every byte, even after the first difference',
        'Hex ignores case. Base64 and base64url never do',
        'hashes verify exits with 1 on a mismatch, so a script can branch on it',
      ]"
      reverse
    >
      Lowercasing a digest before comparing is the classic shortcut, and it's fine for hex. For
      base64 it's a bug, <code class="hashes-code">A</code> and <code class="hashes-code">a</code>
      are different bytes. The panel takes the current digest, uppercases the hex, lowercases the
      base64 and asks <code class="hashes-code">hash_verify</code> about both. One passes. The other
      shouldn't, and doesn't.
      <template #visual>
        <LandingVerify :sample="current" @pause="paused = $event" />
      </template>
    </LandingFeature>

    <section class="hashes-section">
      <div class="mx-auto w-full max-w-[var(--ui-container)] px-8 py-20 sm:px-12 lg:px-16">
        <div class="max-w-2xl">
          <h2 class="text-2xl font-medium tracking-tight text-highlighted sm:text-[1.75rem]">
            {{ spellOutCapital(ALGORITHMS.length) }} algorithms, {{ spellOut(FAMILIES.length) }}
            families
          </h2>
          <p class="mt-4 text-sm leading-6 text-muted">
            {{ spellOutCapital(categorySize("cryptographic")) }} cryptographic ones, from SHA-256 to
            BLAKE3, with the compositions chains actually use: Keccak-256 with its old padding,
            HASH160, double SHA-256, BLAKE2b cut to 32 and 28 bytes. MD5 and SHA-1 sit under legacy,
            broken and still everywhere, next to SHA-0, which never got that far.
            {{ spellOutCapital(categorySize("non-cryptographic")) }}
            checksums for tables and files, and {{ spellOut(categorySize("password")) }} KDFs that
            print the salt they drew. {{ spellOutCapital(HMAC_COUNT) }} of them take a key. The
            rest say no instead of pretending.
          </p>
          <p class="landing-entry">
            <span class="console-tag">Import</span>
            <code>import { algorithms, create } from "@agntn/hashes"</code>
          </p>
        </div>
        <LandingRegistry :sample="current" class="mt-10" @pause="paused = $event" />
      </div>
    </section>

    <LandingFeature
      :title="`${spellOutCapital(TOOLS.length)} tools, one executor`"
      to="/guide/agents"
      link="MCP, Pi, OMP and AI SDK"
      :checks="[
        TOOLS.join(', '),
        'A misspelled argument is an error. salt_hex never turns into a random salt',
        'Input as utf8, hex or base64, so a public key hashes as bytes',
      ]"
      reverse
    >
      Ask a model for a digest and it answers from memory. Give it
      <code class="hashes-code">hash_compute</code> and it answers from code.
      <code class="hashes-code">hashes mcp</code>, the Pi and OMP extensions and
      <code class="hashes-code">@agntn/hashes/ai</code> call the same executors, so they answer
      identically and a fix lands once. This page runs them too, so the dialog shows exactly what a
      model reads for <code class="hashes-code">"{{ SAMPLE_INPUT }}"</code>.
      <template #visual>
        <LandingToolCall :sample="current" @pause="paused = $event" />
      </template>
    </LandingFeature>

    <LandingFeature
      title="Extend FixedHash, call register"
      to="/guide/custom"
      link="Custom algorithms"
      :checks="[
        'A static key, an about block and digest(bytes). Encoding, input and errors are the base class\'s job',
        'BlockHash with a Hasher gets you HMAC as well',
        'register(Class) makes it visible to create, resolveAlgorithm and the tools',
      ]"
    >
      Every built-in is a class, and yours is the same shape, one file. A fixed-length digest only
      has to turn bytes into bytes. <code class="hashes-code">FixedHash</code> does the encodings,
      the result and the error wrapping, and says no to an HMAC key it can't honour. No plugin
      manifest.
      <template #visual>
        <LandingCustom />
      </template>
    </LandingFeature>

    <section class="hashes-section">
      <div class="mx-auto w-full max-w-[var(--ui-container)] px-8 py-20 sm:px-12 lg:px-16">
        <LandingStart />
      </div>
    </section>
  </div>
</template>

<style scoped>
.landing-entry {
  display: flex;
  align-items: baseline;
  gap: 12px;
  margin: 20px 0 0;
  min-width: 0;
}
.landing-entry > .console-tag {
  flex: none;
  margin: 0;
}
.landing-entry > code {
  min-width: 0;
  overflow: hidden;
  font-family: var(--font-mono);
  font-size: 13px;
  text-overflow: ellipsis;
  white-space: nowrap;
  color: var(--ui-text-highlighted);
}
</style>
