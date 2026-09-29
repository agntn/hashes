import { create } from "@agntn/hashes";
import { ALGORITHMS, type AlgorithmEntry } from "../utils/algorithms";

/** The input every panel hashes, and the same text with one bit of its last byte flipped. */
export const SAMPLE_INPUT = "hello world";
export const FLIPPED_INPUT = `${SAMPLE_INPUT.slice(0, -1)}${String.fromCodePoint(SAMPLE_INPUT.codePointAt(SAMPLE_INPUT.length - 1)! ^ 1)}`;

/** The order the landing walks the digests in. Neighbours are kept different on purpose. */
const ORDER: readonly AlgorithmEntry["slug"][] = [
  "sha256",
  "keccak256",
  "blake3",
  "hash160",
  "sha3-256",
  "crc32",
  "blake2b-256",
  "md5",
  "xxhash",
  "sha512-half",
  "ripemd160",
  "blake256",
  "sha1",
  "fnv1a",
  "hash256",
  "blake2s",
  "crc16-xmodem",
  "sha384",
  "blake2b-224",
  "sha3-512",
  "blake2b",
  "sha512",
];

/**
 * Every digest in the registry. The KDFs stay out: each step would run scrypt or 600000 rounds of
 * PBKDF2 in the page. A newcomer missing from `ORDER` joins at the end.
 */
const WALK: readonly AlgorithmEntry[] = [
  ...ORDER.map((slug) => ALGORITHMS.find((row) => row.slug === slug)!),
  ...ALGORITHMS.filter((row) => !ORDER.includes(row.slug) && row.info.family !== "password"),
];

export interface LandingSample {
  entry: AlgorithmEntry;
  /** The digest of `SAMPLE_INPUT` in hex. */
  digest: string;
  /** The digest of `FLIPPED_INPUT` in hex. */
  flipped: string;
  /** One flag per digest bit, most significant first: whether the flipped input changed it. */
  changed: readonly boolean[];
  /** How many of those bits changed. */
  changedCount: number;
}

/**
 * Hashes both inputs with one algorithm and lines up their bits.
 *
 * @param {AlgorithmEntry} entry - A built-in digest.
 * @returns {LandingSample} Both digests and which bits differ.
 */
export function hashSample(entry: AlgorithmEntry): LandingSample {
  const algorithm = create(entry.slug);
  const a = algorithm.hash(SAMPLE_INPUT, { encoding: "binary" }).digest as Uint8Array;
  const b = algorithm.hash(FLIPPED_INPUT, { encoding: "binary" }).digest as Uint8Array;
  const changed = [...a].flatMap((byte, index) =>
    Array.from({ length: 8 }, (_, bit) => (((byte ^ b[index]!) >> (7 - bit)) & 1) === 1),
  );
  return {
    entry,
    digest: String(algorithm.hash(SAMPLE_INPUT).digest),
    flipped: String(algorithm.hash(FLIPPED_INPUT).digest),
    changed,
    changedCount: changed.filter(Boolean).length,
  };
}

/** One clock for every landing panel. The library computes the samples, at build and live. */
export function useLandingHash() {
  const samples = WALK.map((entry) => hashSample(entry));
  const tick = ref(0);
  const paused = ref(false);
  const index = computed(() => tick.value % samples.length);
  const current = computed(() => samples[index.value]!);

  let timer: number | undefined;

  /** Wraps at both ends, so the previous button on the first digest lands on the last one. */
  function step(delta: number) {
    tick.value = (tick.value + delta + samples.length) % samples.length;
  }

  function stopWalk() {
    if (timer !== undefined) {
      window.clearInterval(timer);
      timer = undefined;
    }
  }

  function startWalk() {
    stopWalk();
    if (!import.meta.client || window.matchMedia("(prefers-reduced-motion: reduce)").matches) {
      return;
    }
    timer = window.setInterval(() => {
      if (!paused.value && !document.hidden) {
        step(1);
      }
    }, 4200);
  }

  onMounted(startWalk);
  onUnmounted(stopWalk);

  return { samples, tick, index, paused, current, step };
}
