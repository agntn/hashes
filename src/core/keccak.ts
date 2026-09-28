/**
 * Keccak-f[1600] and its sponge, in plain TypeScript on 32-bit halves. Node's OpenSSL has SHA-3
 * everywhere but Keccak with the original padding only from OpenSSL 3.2, which Node 24 lacks.
 * Each 64-bit lane is two words, low word first, as the state bytes lie little-endian.
 */

/**
 * The ι round constants, low and high words, from the specification's LFSR.
 *
 * @returns {[Uint32Array, Uint32Array]} Low and high words of the 24 constants.
 */
function roundConstants(): [Uint32Array, Uint32Array] {
  const low = new Uint32Array(24);
  const high = new Uint32Array(24);
  let register = 1;
  for (let round = 0; round < 24; round++) {
    for (let bit = 0; bit < 7; bit++) {
      const position = 2 ** bit - 1;
      if (register & 1) {
        if (position < 32) low[round]! |= 1 << position;
        else high[round]! |= 1 << (position - 32);
      }
      register = register & 0x80 ? ((register << 1) ^ 0x171) & 0xff : (register << 1) & 0xff;
    }
  }
  return [low, high];
}

const [RC_LOW, RC_HIGH] = roundConstants();

/**
 * Applies Keccak-f[1600] to the state in place. The round is unrolled with every rotation offset
 * and π destination written in, so it works on local variables only: θ (column parities), ρ and π
 * (rotate each lane into its new place), χ (mix along the row) and ι (round constant).
 *
 * @param state - Fifty words: lane i is `state[2i]` (low) and `state[2i + 1]` (high).
 */
function permute(state: Uint32Array): void {
  let l0 = state[0]! | 0;
  let h0 = state[1]! | 0;
  let l1 = state[2]! | 0;
  let h1 = state[3]! | 0;
  let l2 = state[4]! | 0;
  let h2 = state[5]! | 0;
  let l3 = state[6]! | 0;
  let h3 = state[7]! | 0;
  let l4 = state[8]! | 0;
  let h4 = state[9]! | 0;
  let l5 = state[10]! | 0;
  let h5 = state[11]! | 0;
  let l6 = state[12]! | 0;
  let h6 = state[13]! | 0;
  let l7 = state[14]! | 0;
  let h7 = state[15]! | 0;
  let l8 = state[16]! | 0;
  let h8 = state[17]! | 0;
  let l9 = state[18]! | 0;
  let h9 = state[19]! | 0;
  let l10 = state[20]! | 0;
  let h10 = state[21]! | 0;
  let l11 = state[22]! | 0;
  let h11 = state[23]! | 0;
  let l12 = state[24]! | 0;
  let h12 = state[25]! | 0;
  let l13 = state[26]! | 0;
  let h13 = state[27]! | 0;
  let l14 = state[28]! | 0;
  let h14 = state[29]! | 0;
  let l15 = state[30]! | 0;
  let h15 = state[31]! | 0;
  let l16 = state[32]! | 0;
  let h16 = state[33]! | 0;
  let l17 = state[34]! | 0;
  let h17 = state[35]! | 0;
  let l18 = state[36]! | 0;
  let h18 = state[37]! | 0;
  let l19 = state[38]! | 0;
  let h19 = state[39]! | 0;
  let l20 = state[40]! | 0;
  let h20 = state[41]! | 0;
  let l21 = state[42]! | 0;
  let h21 = state[43]! | 0;
  let l22 = state[44]! | 0;
  let h22 = state[45]! | 0;
  let l23 = state[46]! | 0;
  let h23 = state[47]! | 0;
  let l24 = state[48]! | 0;
  let h24 = state[49]! | 0;
  for (let round = 0; round < 24; round++) {
    const cL0 = l0 ^ l5 ^ l10 ^ l15 ^ l20;
    const cH0 = h0 ^ h5 ^ h10 ^ h15 ^ h20;
    const cL1 = l1 ^ l6 ^ l11 ^ l16 ^ l21;
    const cH1 = h1 ^ h6 ^ h11 ^ h16 ^ h21;
    const cL2 = l2 ^ l7 ^ l12 ^ l17 ^ l22;
    const cH2 = h2 ^ h7 ^ h12 ^ h17 ^ h22;
    const cL3 = l3 ^ l8 ^ l13 ^ l18 ^ l23;
    const cH3 = h3 ^ h8 ^ h13 ^ h18 ^ h23;
    const cL4 = l4 ^ l9 ^ l14 ^ l19 ^ l24;
    const cH4 = h4 ^ h9 ^ h14 ^ h19 ^ h24;
    const dL0 = cL4 ^ ((cL1 << 1) | (cH1 >>> 31));
    const dH0 = cH4 ^ ((cH1 << 1) | (cL1 >>> 31));
    const dL1 = cL0 ^ ((cL2 << 1) | (cH2 >>> 31));
    const dH1 = cH0 ^ ((cH2 << 1) | (cL2 >>> 31));
    const dL2 = cL1 ^ ((cL3 << 1) | (cH3 >>> 31));
    const dH2 = cH1 ^ ((cH3 << 1) | (cL3 >>> 31));
    const dL3 = cL2 ^ ((cL4 << 1) | (cH4 >>> 31));
    const dH3 = cH2 ^ ((cH4 << 1) | (cL4 >>> 31));
    const dL4 = cL3 ^ ((cL0 << 1) | (cH0 >>> 31));
    const dH4 = cH3 ^ ((cH0 << 1) | (cL0 >>> 31));
    l0 ^= dL0;
    h0 ^= dH0;
    l1 ^= dL1;
    h1 ^= dH1;
    l2 ^= dL2;
    h2 ^= dH2;
    l3 ^= dL3;
    h3 ^= dH3;
    l4 ^= dL4;
    h4 ^= dH4;
    l5 ^= dL0;
    h5 ^= dH0;
    l6 ^= dL1;
    h6 ^= dH1;
    l7 ^= dL2;
    h7 ^= dH2;
    l8 ^= dL3;
    h8 ^= dH3;
    l9 ^= dL4;
    h9 ^= dH4;
    l10 ^= dL0;
    h10 ^= dH0;
    l11 ^= dL1;
    h11 ^= dH1;
    l12 ^= dL2;
    h12 ^= dH2;
    l13 ^= dL3;
    h13 ^= dH3;
    l14 ^= dL4;
    h14 ^= dH4;
    l15 ^= dL0;
    h15 ^= dH0;
    l16 ^= dL1;
    h16 ^= dH1;
    l17 ^= dL2;
    h17 ^= dH2;
    l18 ^= dL3;
    h18 ^= dH3;
    l19 ^= dL4;
    h19 ^= dH4;
    l20 ^= dL0;
    h20 ^= dH0;
    l21 ^= dL1;
    h21 ^= dH1;
    l22 ^= dL2;
    h22 ^= dH2;
    l23 ^= dL3;
    h23 ^= dH3;
    l24 ^= dL4;
    h24 ^= dH4;
    const bL0 = l0;
    const bH0 = h0;
    const bL10 = (l1 << 1) | (h1 >>> 31);
    const bH10 = (h1 << 1) | (l1 >>> 31);
    const bL20 = (h2 << 30) | (l2 >>> 2);
    const bH20 = (l2 << 30) | (h2 >>> 2);
    const bL5 = (l3 << 28) | (h3 >>> 4);
    const bH5 = (h3 << 28) | (l3 >>> 4);
    const bL15 = (l4 << 27) | (h4 >>> 5);
    const bH15 = (h4 << 27) | (l4 >>> 5);
    const bL16 = (h5 << 4) | (l5 >>> 28);
    const bH16 = (l5 << 4) | (h5 >>> 28);
    const bL1 = (h6 << 12) | (l6 >>> 20);
    const bH1 = (l6 << 12) | (h6 >>> 20);
    const bL11 = (l7 << 6) | (h7 >>> 26);
    const bH11 = (h7 << 6) | (l7 >>> 26);
    const bL21 = (h8 << 23) | (l8 >>> 9);
    const bH21 = (l8 << 23) | (h8 >>> 9);
    const bL6 = (l9 << 20) | (h9 >>> 12);
    const bH6 = (h9 << 20) | (l9 >>> 12);
    const bL7 = (l10 << 3) | (h10 >>> 29);
    const bH7 = (h10 << 3) | (l10 >>> 29);
    const bL17 = (l11 << 10) | (h11 >>> 22);
    const bH17 = (h11 << 10) | (l11 >>> 22);
    const bL2 = (h12 << 11) | (l12 >>> 21);
    const bH2 = (l12 << 11) | (h12 >>> 21);
    const bL12 = (l13 << 25) | (h13 >>> 7);
    const bH12 = (h13 << 25) | (l13 >>> 7);
    const bL22 = (h14 << 7) | (l14 >>> 25);
    const bH22 = (l14 << 7) | (h14 >>> 25);
    const bL23 = (h15 << 9) | (l15 >>> 23);
    const bH23 = (l15 << 9) | (h15 >>> 23);
    const bL8 = (h16 << 13) | (l16 >>> 19);
    const bH8 = (l16 << 13) | (h16 >>> 19);
    const bL18 = (l17 << 15) | (h17 >>> 17);
    const bH18 = (h17 << 15) | (l17 >>> 17);
    const bL3 = (l18 << 21) | (h18 >>> 11);
    const bH3 = (h18 << 21) | (l18 >>> 11);
    const bL13 = (l19 << 8) | (h19 >>> 24);
    const bH13 = (h19 << 8) | (l19 >>> 24);
    const bL14 = (l20 << 18) | (h20 >>> 14);
    const bH14 = (h20 << 18) | (l20 >>> 14);
    const bL24 = (l21 << 2) | (h21 >>> 30);
    const bH24 = (h21 << 2) | (l21 >>> 30);
    const bL9 = (h22 << 29) | (l22 >>> 3);
    const bH9 = (l22 << 29) | (h22 >>> 3);
    const bL19 = (h23 << 24) | (l23 >>> 8);
    const bH19 = (l23 << 24) | (h23 >>> 8);
    const bL4 = (l24 << 14) | (h24 >>> 18);
    const bH4 = (h24 << 14) | (l24 >>> 18);
    l0 = bL0 ^ (~bL1 & bL2);
    h0 = bH0 ^ (~bH1 & bH2);
    l1 = bL1 ^ (~bL2 & bL3);
    h1 = bH1 ^ (~bH2 & bH3);
    l2 = bL2 ^ (~bL3 & bL4);
    h2 = bH2 ^ (~bH3 & bH4);
    l3 = bL3 ^ (~bL4 & bL0);
    h3 = bH3 ^ (~bH4 & bH0);
    l4 = bL4 ^ (~bL0 & bL1);
    h4 = bH4 ^ (~bH0 & bH1);
    l5 = bL5 ^ (~bL6 & bL7);
    h5 = bH5 ^ (~bH6 & bH7);
    l6 = bL6 ^ (~bL7 & bL8);
    h6 = bH6 ^ (~bH7 & bH8);
    l7 = bL7 ^ (~bL8 & bL9);
    h7 = bH7 ^ (~bH8 & bH9);
    l8 = bL8 ^ (~bL9 & bL5);
    h8 = bH8 ^ (~bH9 & bH5);
    l9 = bL9 ^ (~bL5 & bL6);
    h9 = bH9 ^ (~bH5 & bH6);
    l10 = bL10 ^ (~bL11 & bL12);
    h10 = bH10 ^ (~bH11 & bH12);
    l11 = bL11 ^ (~bL12 & bL13);
    h11 = bH11 ^ (~bH12 & bH13);
    l12 = bL12 ^ (~bL13 & bL14);
    h12 = bH12 ^ (~bH13 & bH14);
    l13 = bL13 ^ (~bL14 & bL10);
    h13 = bH13 ^ (~bH14 & bH10);
    l14 = bL14 ^ (~bL10 & bL11);
    h14 = bH14 ^ (~bH10 & bH11);
    l15 = bL15 ^ (~bL16 & bL17);
    h15 = bH15 ^ (~bH16 & bH17);
    l16 = bL16 ^ (~bL17 & bL18);
    h16 = bH16 ^ (~bH17 & bH18);
    l17 = bL17 ^ (~bL18 & bL19);
    h17 = bH17 ^ (~bH18 & bH19);
    l18 = bL18 ^ (~bL19 & bL15);
    h18 = bH18 ^ (~bH19 & bH15);
    l19 = bL19 ^ (~bL15 & bL16);
    h19 = bH19 ^ (~bH15 & bH16);
    l20 = bL20 ^ (~bL21 & bL22);
    h20 = bH20 ^ (~bH21 & bH22);
    l21 = bL21 ^ (~bL22 & bL23);
    h21 = bH21 ^ (~bH22 & bH23);
    l22 = bL22 ^ (~bL23 & bL24);
    h22 = bH22 ^ (~bH23 & bH24);
    l23 = bL23 ^ (~bL24 & bL20);
    h23 = bH23 ^ (~bH24 & bH20);
    l24 = bL24 ^ (~bL20 & bL21);
    h24 = bH24 ^ (~bH20 & bH21);
    l0 ^= RC_LOW[round]!;
    h0 ^= RC_HIGH[round]!;
  }
  state[0] = l0;
  state[1] = h0;
  state[2] = l1;
  state[3] = h1;
  state[4] = l2;
  state[5] = h2;
  state[6] = l3;
  state[7] = h3;
  state[8] = l4;
  state[9] = h4;
  state[10] = l5;
  state[11] = h5;
  state[12] = l6;
  state[13] = h6;
  state[14] = l7;
  state[15] = h7;
  state[16] = l8;
  state[17] = h8;
  state[18] = l9;
  state[19] = h9;
  state[20] = l10;
  state[21] = h10;
  state[22] = l11;
  state[23] = h11;
  state[24] = l12;
  state[25] = h12;
  state[26] = l13;
  state[27] = h13;
  state[28] = l14;
  state[29] = h14;
  state[30] = l15;
  state[31] = h15;
  state[32] = l16;
  state[33] = h16;
  state[34] = l17;
  state[35] = h17;
  state[36] = l18;
  state[37] = h18;
  state[38] = l19;
  state[39] = h19;
  state[40] = l20;
  state[41] = h20;
  state[42] = l21;
  state[43] = h21;
  state[44] = l22;
  state[45] = h22;
  state[46] = l23;
  state[47] = h23;
  state[48] = l24;
  state[49] = h24;
}

if (new Uint8Array(new Uint32Array([1]).buffer)[0] !== 1) {
  throw new Error("Keccak here reads the state as little-endian bytes");
}

/**
 * Hashes with a Keccak sponge.
 *
 * @param data - Bytes to hash.
 * @param rate - Bytes absorbed per permutation: 200 minus twice the output length.
 * @param suffix - Domain bits before the final padding: 0x01 for Keccak, 0x06 for SHA-3.
 * @param length - Output bytes, at most \`rate\`.
 * @returns {Uint8Array} The digest.
 */
export function keccakSponge(
  data: Uint8Array,
  rate: number,
  suffix: number,
  length: number,
): Uint8Array {
  const state = new Uint32Array(50);
  const bytes = new Uint8Array(state.buffer);
  let offset = 0;
  for (; offset + rate <= data.length; offset += rate) {
    for (let index = 0; index < rate; index++) bytes[index] = bytes[index]! ^ data[offset + index]!;
    permute(state);
  }
  const tail = data.length - offset;
  for (let index = 0; index < tail; index++) bytes[index] = bytes[index]! ^ data[offset + index]!;
  bytes[tail] = bytes[tail]! ^ suffix;
  bytes[rate - 1] = bytes[rate - 1]! ^ 0x80;
  permute(state);
  return bytes.slice(0, length);
}
