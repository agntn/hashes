/**
 * The Keccak-f[1600] sponge behind SHA3-256, SHA3-512 (FIPS 202) and the Keccak-256 Ethereum
 * kept from before FIPS 202 changed the padding. The 25 lanes are 64-bit, held as a low then a
 * high 32-bit half, so the state is fifty int32 values.
 */
import { Hasher, assertBytes, viewOf, wordsToBytes } from "./hasher.ts";

/** Domain byte FIPS 202 puts after a SHA-3 message. */
export const SHA3_PADDING = 0x06;

/** Domain byte of the original Keccak submission, which Ethereum kept. */
export const KECCAK_PADDING = 0x01;

/** Round constants, low then high half. */
const RC = /* @__PURE__ */ new Int32Array([
  0x00000001, 0x00000000, 0x00008082, 0x00000000, 0x0000808a, 0x80000000, 0x80008000, 0x80000000,
  0x0000808b, 0x00000000, 0x80000001, 0x00000000, 0x80008081, 0x80000000, 0x00008009, 0x80000000,
  0x0000008a, 0x00000000, 0x00000088, 0x00000000, 0x80008009, 0x00000000, 0x8000000a, 0x00000000,
  0x8000808b, 0x00000000, 0x0000008b, 0x80000000, 0x00008089, 0x80000000, 0x00008003, 0x80000000,
  0x00008002, 0x80000000, 0x00000080, 0x80000000, 0x0000800a, 0x00000000, 0x8000000a, 0x80000000,
  0x80008081, 0x80000000, 0x00008080, 0x80000000, 0x80000001, 0x00000000, 0x80008008, 0x80000000,
]);

/**
 * Runs the 24 rounds of Keccak-f[1600] on the state. Every lane lives in two locals, `lN` (low)
 * and `hN` (high), for lane `N = x + 5y`; `bN` holds the lanes after rho and pi.
 *
 * @param s - Fifty halves, lane `N` at `2N` (low) and `2N + 1` (high), updated in place.
 */
function permute(s: Int32Array): void {
  let l0 = s[0]!;
  let h0 = s[1]!;
  let l1 = s[2]!;
  let h1 = s[3]!;
  let l2 = s[4]!;
  let h2 = s[5]!;
  let l3 = s[6]!;
  let h3 = s[7]!;
  let l4 = s[8]!;
  let h4 = s[9]!;
  let l5 = s[10]!;
  let h5 = s[11]!;
  let l6 = s[12]!;
  let h6 = s[13]!;
  let l7 = s[14]!;
  let h7 = s[15]!;
  let l8 = s[16]!;
  let h8 = s[17]!;
  let l9 = s[18]!;
  let h9 = s[19]!;
  let l10 = s[20]!;
  let h10 = s[21]!;
  let l11 = s[22]!;
  let h11 = s[23]!;
  let l12 = s[24]!;
  let h12 = s[25]!;
  let l13 = s[26]!;
  let h13 = s[27]!;
  let l14 = s[28]!;
  let h14 = s[29]!;
  let l15 = s[30]!;
  let h15 = s[31]!;
  let l16 = s[32]!;
  let h16 = s[33]!;
  let l17 = s[34]!;
  let h17 = s[35]!;
  let l18 = s[36]!;
  let h18 = s[37]!;
  let l19 = s[38]!;
  let h19 = s[39]!;
  let l20 = s[40]!;
  let h20 = s[41]!;
  let l21 = s[42]!;
  let h21 = s[43]!;
  let l22 = s[44]!;
  let h22 = s[45]!;
  let l23 = s[46]!;
  let h23 = s[47]!;
  let l24 = s[48]!;
  let h24 = s[49]!;
  let cl0 = 0;
  let ch0 = 0;
  let cl1 = 0;
  let ch1 = 0;
  let cl2 = 0;
  let ch2 = 0;
  let cl3 = 0;
  let ch3 = 0;
  let cl4 = 0;
  let ch4 = 0;
  let dl = 0;
  let dh = 0;
  let bl0 = 0;
  let bh0 = 0;
  let bl1 = 0;
  let bh1 = 0;
  let bl2 = 0;
  let bh2 = 0;
  let bl3 = 0;
  let bh3 = 0;
  let bl4 = 0;
  let bh4 = 0;
  let bl5 = 0;
  let bh5 = 0;
  let bl6 = 0;
  let bh6 = 0;
  let bl7 = 0;
  let bh7 = 0;
  let bl8 = 0;
  let bh8 = 0;
  let bl9 = 0;
  let bh9 = 0;
  let bl10 = 0;
  let bh10 = 0;
  let bl11 = 0;
  let bh11 = 0;
  let bl12 = 0;
  let bh12 = 0;
  let bl13 = 0;
  let bh13 = 0;
  let bl14 = 0;
  let bh14 = 0;
  let bl15 = 0;
  let bh15 = 0;
  let bl16 = 0;
  let bh16 = 0;
  let bl17 = 0;
  let bh17 = 0;
  let bl18 = 0;
  let bh18 = 0;
  let bl19 = 0;
  let bh19 = 0;
  let bl20 = 0;
  let bh20 = 0;
  let bl21 = 0;
  let bh21 = 0;
  let bl22 = 0;
  let bh22 = 0;
  let bl23 = 0;
  let bh23 = 0;
  let bl24 = 0;
  let bh24 = 0;
  for (let round = 0; round < 48; round += 2) {
    // Theta: xor each column with the parities of its two neighbours.
    cl0 = l0 ^ l5 ^ l10 ^ l15 ^ l20;
    ch0 = h0 ^ h5 ^ h10 ^ h15 ^ h20;
    cl1 = l1 ^ l6 ^ l11 ^ l16 ^ l21;
    ch1 = h1 ^ h6 ^ h11 ^ h16 ^ h21;
    cl2 = l2 ^ l7 ^ l12 ^ l17 ^ l22;
    ch2 = h2 ^ h7 ^ h12 ^ h17 ^ h22;
    cl3 = l3 ^ l8 ^ l13 ^ l18 ^ l23;
    ch3 = h3 ^ h8 ^ h13 ^ h18 ^ h23;
    cl4 = l4 ^ l9 ^ l14 ^ l19 ^ l24;
    ch4 = h4 ^ h9 ^ h14 ^ h19 ^ h24;
    dl = cl4 ^ ((cl1 << 1) | (ch1 >>> 31));
    dh = ch4 ^ ((ch1 << 1) | (cl1 >>> 31));
    l0 ^= dl;
    h0 ^= dh;
    l5 ^= dl;
    h5 ^= dh;
    l10 ^= dl;
    h10 ^= dh;
    l15 ^= dl;
    h15 ^= dh;
    l20 ^= dl;
    h20 ^= dh;
    dl = cl0 ^ ((cl2 << 1) | (ch2 >>> 31));
    dh = ch0 ^ ((ch2 << 1) | (cl2 >>> 31));
    l1 ^= dl;
    h1 ^= dh;
    l6 ^= dl;
    h6 ^= dh;
    l11 ^= dl;
    h11 ^= dh;
    l16 ^= dl;
    h16 ^= dh;
    l21 ^= dl;
    h21 ^= dh;
    dl = cl1 ^ ((cl3 << 1) | (ch3 >>> 31));
    dh = ch1 ^ ((ch3 << 1) | (cl3 >>> 31));
    l2 ^= dl;
    h2 ^= dh;
    l7 ^= dl;
    h7 ^= dh;
    l12 ^= dl;
    h12 ^= dh;
    l17 ^= dl;
    h17 ^= dh;
    l22 ^= dl;
    h22 ^= dh;
    dl = cl2 ^ ((cl4 << 1) | (ch4 >>> 31));
    dh = ch2 ^ ((ch4 << 1) | (cl4 >>> 31));
    l3 ^= dl;
    h3 ^= dh;
    l8 ^= dl;
    h8 ^= dh;
    l13 ^= dl;
    h13 ^= dh;
    l18 ^= dl;
    h18 ^= dh;
    l23 ^= dl;
    h23 ^= dh;
    dl = cl3 ^ ((cl0 << 1) | (ch0 >>> 31));
    dh = ch3 ^ ((ch0 << 1) | (cl0 >>> 31));
    l4 ^= dl;
    h4 ^= dh;
    l9 ^= dl;
    h9 ^= dh;
    l14 ^= dl;
    h14 ^= dh;
    l19 ^= dl;
    h19 ^= dh;
    l24 ^= dl;
    h24 ^= dh;
    // Rho and pi: rotate each lane into its new place.
    bl0 = l0;
    bh0 = h0;
    bl1 = (h6 << 12) | (l6 >>> 20);
    bh1 = (l6 << 12) | (h6 >>> 20);
    bl2 = (h12 << 11) | (l12 >>> 21);
    bh2 = (l12 << 11) | (h12 >>> 21);
    bl3 = (l18 << 21) | (h18 >>> 11);
    bh3 = (h18 << 21) | (l18 >>> 11);
    bl4 = (l24 << 14) | (h24 >>> 18);
    bh4 = (h24 << 14) | (l24 >>> 18);
    bl5 = (l3 << 28) | (h3 >>> 4);
    bh5 = (h3 << 28) | (l3 >>> 4);
    bl6 = (l9 << 20) | (h9 >>> 12);
    bh6 = (h9 << 20) | (l9 >>> 12);
    bl7 = (l10 << 3) | (h10 >>> 29);
    bh7 = (h10 << 3) | (l10 >>> 29);
    bl8 = (h16 << 13) | (l16 >>> 19);
    bh8 = (l16 << 13) | (h16 >>> 19);
    bl9 = (h22 << 29) | (l22 >>> 3);
    bh9 = (l22 << 29) | (h22 >>> 3);
    bl10 = (l1 << 1) | (h1 >>> 31);
    bh10 = (h1 << 1) | (l1 >>> 31);
    bl11 = (l7 << 6) | (h7 >>> 26);
    bh11 = (h7 << 6) | (l7 >>> 26);
    bl12 = (l13 << 25) | (h13 >>> 7);
    bh12 = (h13 << 25) | (l13 >>> 7);
    bl13 = (l19 << 8) | (h19 >>> 24);
    bh13 = (h19 << 8) | (l19 >>> 24);
    bl14 = (l20 << 18) | (h20 >>> 14);
    bh14 = (h20 << 18) | (l20 >>> 14);
    bl15 = (l4 << 27) | (h4 >>> 5);
    bh15 = (h4 << 27) | (l4 >>> 5);
    bl16 = (h5 << 4) | (l5 >>> 28);
    bh16 = (l5 << 4) | (h5 >>> 28);
    bl17 = (l11 << 10) | (h11 >>> 22);
    bh17 = (h11 << 10) | (l11 >>> 22);
    bl18 = (l17 << 15) | (h17 >>> 17);
    bh18 = (h17 << 15) | (l17 >>> 17);
    bl19 = (h23 << 24) | (l23 >>> 8);
    bh19 = (l23 << 24) | (h23 >>> 8);
    bl20 = (h2 << 30) | (l2 >>> 2);
    bh20 = (l2 << 30) | (h2 >>> 2);
    bl21 = (h8 << 23) | (l8 >>> 9);
    bh21 = (l8 << 23) | (h8 >>> 9);
    bl22 = (h14 << 7) | (l14 >>> 25);
    bh22 = (l14 << 7) | (h14 >>> 25);
    bl23 = (h15 << 9) | (l15 >>> 23);
    bh23 = (l15 << 9) | (h15 >>> 23);
    bl24 = (l21 << 2) | (h21 >>> 30);
    bh24 = (h21 << 2) | (l21 >>> 30);
    // Chi: each lane xors in the NOT of the next lane in its row, AND the one after that.
    l0 = bl0 ^ (~bl1 & bl2);
    h0 = bh0 ^ (~bh1 & bh2);
    l1 = bl1 ^ (~bl2 & bl3);
    h1 = bh1 ^ (~bh2 & bh3);
    l2 = bl2 ^ (~bl3 & bl4);
    h2 = bh2 ^ (~bh3 & bh4);
    l3 = bl3 ^ (~bl4 & bl0);
    h3 = bh3 ^ (~bh4 & bh0);
    l4 = bl4 ^ (~bl0 & bl1);
    h4 = bh4 ^ (~bh0 & bh1);
    l5 = bl5 ^ (~bl6 & bl7);
    h5 = bh5 ^ (~bh6 & bh7);
    l6 = bl6 ^ (~bl7 & bl8);
    h6 = bh6 ^ (~bh7 & bh8);
    l7 = bl7 ^ (~bl8 & bl9);
    h7 = bh7 ^ (~bh8 & bh9);
    l8 = bl8 ^ (~bl9 & bl5);
    h8 = bh8 ^ (~bh9 & bh5);
    l9 = bl9 ^ (~bl5 & bl6);
    h9 = bh9 ^ (~bh5 & bh6);
    l10 = bl10 ^ (~bl11 & bl12);
    h10 = bh10 ^ (~bh11 & bh12);
    l11 = bl11 ^ (~bl12 & bl13);
    h11 = bh11 ^ (~bh12 & bh13);
    l12 = bl12 ^ (~bl13 & bl14);
    h12 = bh12 ^ (~bh13 & bh14);
    l13 = bl13 ^ (~bl14 & bl10);
    h13 = bh13 ^ (~bh14 & bh10);
    l14 = bl14 ^ (~bl10 & bl11);
    h14 = bh14 ^ (~bh10 & bh11);
    l15 = bl15 ^ (~bl16 & bl17);
    h15 = bh15 ^ (~bh16 & bh17);
    l16 = bl16 ^ (~bl17 & bl18);
    h16 = bh16 ^ (~bh17 & bh18);
    l17 = bl17 ^ (~bl18 & bl19);
    h17 = bh17 ^ (~bh18 & bh19);
    l18 = bl18 ^ (~bl19 & bl15);
    h18 = bh18 ^ (~bh19 & bh15);
    l19 = bl19 ^ (~bl15 & bl16);
    h19 = bh19 ^ (~bh15 & bh16);
    l20 = bl20 ^ (~bl21 & bl22);
    h20 = bh20 ^ (~bh21 & bh22);
    l21 = bl21 ^ (~bl22 & bl23);
    h21 = bh21 ^ (~bh22 & bh23);
    l22 = bl22 ^ (~bl23 & bl24);
    h22 = bh22 ^ (~bh23 & bh24);
    l23 = bl23 ^ (~bl24 & bl20);
    h23 = bh23 ^ (~bh24 & bh20);
    l24 = bl24 ^ (~bl20 & bl21);
    h24 = bh24 ^ (~bh20 & bh21);
    // Iota.
    l0 ^= RC[round]!;
    h0 ^= RC[round + 1]!;
  }
  s[0] = l0;
  s[1] = h0;
  s[2] = l1;
  s[3] = h1;
  s[4] = l2;
  s[5] = h2;
  s[6] = l3;
  s[7] = h3;
  s[8] = l4;
  s[9] = h4;
  s[10] = l5;
  s[11] = h5;
  s[12] = l6;
  s[13] = h6;
  s[14] = l7;
  s[15] = h7;
  s[16] = l8;
  s[17] = h8;
  s[18] = l9;
  s[19] = h9;
  s[20] = l10;
  s[21] = h10;
  s[22] = l11;
  s[23] = h11;
  s[24] = l12;
  s[25] = h12;
  s[26] = l13;
  s[27] = h13;
  s[28] = l14;
  s[29] = h14;
  s[30] = l15;
  s[31] = h15;
  s[32] = l16;
  s[33] = h16;
  s[34] = l17;
  s[35] = h17;
  s[36] = l18;
  s[37] = h18;
  s[38] = l19;
  s[39] = h19;
  s[40] = l20;
  s[41] = h20;
  s[42] = l21;
  s[43] = h21;
  s[44] = l22;
  s[45] = h22;
  s[46] = l23;
  s[47] = h23;
  s[48] = l24;
  s[49] = h24;
}

/** A Keccak-f[1600] sponge with a fixed output no longer than one rate block. */
export class KeccakHasher extends Hasher {
  readonly blockLength: number;
  readonly outputLength: number;
  /** Domain byte xored in after the message: `SHA3_PADDING` or `KECCAK_PADDING`. */
  private readonly suffix: number;
  private readonly state = new Int32Array(50);
  /** Bytes absorbed into the current block. */
  private position = 0;

  /**
   * @param outputLength - Digest bytes; the rate is 200 minus twice that.
   * @param suffix - `SHA3_PADDING` or `KECCAK_PADDING`.
   */
  constructor(outputLength: number, suffix: number) {
    super();
    this.outputLength = outputLength;
    this.blockLength = 200 - 2 * outputLength;
    this.suffix = suffix;
  }

  update(data: Uint8Array): this {
    assertBytes(data, "data");
    const { state, blockLength: rate } = this;
    let offset = 0;
    while (offset < data.length) {
      if (this.position === 0 && data.length - offset >= rate) {
        const view = viewOf(data);
        for (; data.length - offset >= rate; offset += rate) {
          for (let i = 0; i < rate; i += 4)
            state[i >> 2] = state[i >> 2]! ^ view.getInt32(offset + i, true);
          permute(state);
        }
        continue;
      }
      const end = Math.min(data.length, offset + rate - this.position);
      for (; offset < end; offset++, this.position++) {
        state[this.position >> 2] =
          state[this.position >> 2]! ^ (data[offset]! << ((this.position & 3) << 3));
      }
      if (this.position === rate) {
        permute(state);
        this.position = 0;
      }
    }
    return this;
  }

  digestInto(out: Uint8Array): void {
    const { state, position } = this;
    const last = this.blockLength - 1;
    state[position >> 2] = state[position >> 2]! ^ (this.suffix << ((position & 3) << 3));
    state[last >> 2] = state[last >> 2]! ^ (0x80 << ((last & 3) << 3));
    permute(state);
    wordsToBytes(state, out, this.outputLength, true);
  }

  load(source: this): this {
    this.state.set(source.state);
    this.position = source.position;
    return this;
  }
}

/**
 * Keccak-256 with the original padding, as Ethereum hashes with it.
 *
 * @param data - Bytes to hash.
 * @returns {Uint8Array} 32 bytes.
 */
export function keccak256(data: Uint8Array): Uint8Array {
  return new KeccakHasher(32, KECCAK_PADDING).update(data).digest();
}

/**
 * SHA3-256 (FIPS 202).
 *
 * @param data - Bytes to hash.
 * @returns {Uint8Array} 32 bytes.
 */
export function sha3_256(data: Uint8Array): Uint8Array {
  return new KeccakHasher(32, SHA3_PADDING).update(data).digest();
}
