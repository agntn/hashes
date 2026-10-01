/**
 * RIPEMD-128 runs RIPEMD-160's two lines for four rounds on four words, without the rotation by
 * 10. RIPEMD-256 and RIPEMD-320 run the lines of RIPEMD-128 and RIPEMD-160 from their own initial
 * value, swap one word between them after each round and keep both. RIPEMD-320 repeats the
 * RIPEMD-160 rounds here, so a bundle that hashes RIPEMD-160 alone carries none of it.
 */
import { MerkleDamgard } from "./hasher.ts";
import { RL, RR, SL, SR } from "./ripemd160.ts";

/** The block's words, shared: hashing is synchronous. */
const X = new Int32Array(16);

/** RIPEMD-128. */
export class Ripemd128Hasher extends MerkleDamgard {
  protected readonly state = new Int32Array([0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476]);

  constructor() {
    super(64, 16, true);
  }

  protected compress(view: DataView, offset: number): void {
    const s = this.state;
    const x = X;
    for (let i = 0; i < 16; i++) x[i] = view.getInt32(offset + i * 4, true);
    let al = s[0]!;
    let bl = s[1]!;
    let cl = s[2]!;
    let dl = s[3]!;
    let ar = al;
    let br = bl;
    let cr = cl;
    let dr = dl;
    let t = 0;
    let r = 0;
    for (let i = 0; i < 16; i++) {
      t = (al + (bl ^ cl ^ dl) + x[RL[i]!]!) | 0;
      r = SL[i]!;
      al = dl;
      dl = cl;
      cl = bl;
      bl = (t << r) | (t >>> (32 - r));
      t = (ar + ((br & dr) | (cr & ~dr)) + x[RR[i]!]! + 0x50a28be6) | 0;
      r = SR[i]!;
      ar = dr;
      dr = cr;
      cr = br;
      br = (t << r) | (t >>> (32 - r));
    }
    for (let i = 16; i < 32; i++) {
      t = (al + ((bl & cl) | (~bl & dl)) + x[RL[i]!]! + 0x5a827999) | 0;
      r = SL[i]!;
      al = dl;
      dl = cl;
      cl = bl;
      bl = (t << r) | (t >>> (32 - r));
      t = (ar + ((br | ~cr) ^ dr) + x[RR[i]!]! + 0x5c4dd124) | 0;
      r = SR[i]!;
      ar = dr;
      dr = cr;
      cr = br;
      br = (t << r) | (t >>> (32 - r));
    }
    for (let i = 32; i < 48; i++) {
      t = (al + ((bl | ~cl) ^ dl) + x[RL[i]!]! + 0x6ed9eba1) | 0;
      r = SL[i]!;
      al = dl;
      dl = cl;
      cl = bl;
      bl = (t << r) | (t >>> (32 - r));
      t = (ar + ((br & cr) | (~br & dr)) + x[RR[i]!]! + 0x6d703ef3) | 0;
      r = SR[i]!;
      ar = dr;
      dr = cr;
      cr = br;
      br = (t << r) | (t >>> (32 - r));
    }
    for (let i = 48; i < 64; i++) {
      t = (al + ((bl & dl) | (cl & ~dl)) + x[RL[i]!]! + 0x8f1bbcdc) | 0;
      r = SL[i]!;
      al = dl;
      dl = cl;
      cl = bl;
      bl = (t << r) | (t >>> (32 - r));
      t = (ar + (br ^ cr ^ dr) + x[RR[i]!]!) | 0;
      r = SR[i]!;
      ar = dr;
      dr = cr;
      cr = br;
      br = (t << r) | (t >>> (32 - r));
    }
    t = (s[1]! + cl + dr) | 0;
    s[1] = (s[2]! + dl + ar) | 0;
    s[2] = (s[3]! + al + br) | 0;
    s[3] = (s[0]! + bl + cr) | 0;
    s[0] = t;
  }
}

/** RIPEMD-256. */
export class Ripemd256Hasher extends MerkleDamgard {
  protected readonly state = new Int32Array([
    0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0x76543210, 0xfedcba98, 0x89abcdef, 0x01234567,
  ]);

  constructor() {
    super(64, 32, true);
  }

  protected compress(view: DataView, offset: number): void {
    const s = this.state;
    const x = X;
    for (let i = 0; i < 16; i++) x[i] = view.getInt32(offset + i * 4, true);
    let al = s[0]!;
    let bl = s[1]!;
    let cl = s[2]!;
    let dl = s[3]!;
    let ar = s[4]!;
    let br = s[5]!;
    let cr = s[6]!;
    let dr = s[7]!;
    let t = 0;
    let r = 0;
    for (let i = 0; i < 16; i++) {
      t = (al + (bl ^ cl ^ dl) + x[RL[i]!]!) | 0;
      r = SL[i]!;
      al = dl;
      dl = cl;
      cl = bl;
      bl = (t << r) | (t >>> (32 - r));
      t = (ar + ((br & dr) | (cr & ~dr)) + x[RR[i]!]! + 0x50a28be6) | 0;
      r = SR[i]!;
      ar = dr;
      dr = cr;
      cr = br;
      br = (t << r) | (t >>> (32 - r));
    }
    t = al;
    al = ar;
    ar = t;
    for (let i = 16; i < 32; i++) {
      t = (al + ((bl & cl) | (~bl & dl)) + x[RL[i]!]! + 0x5a827999) | 0;
      r = SL[i]!;
      al = dl;
      dl = cl;
      cl = bl;
      bl = (t << r) | (t >>> (32 - r));
      t = (ar + ((br | ~cr) ^ dr) + x[RR[i]!]! + 0x5c4dd124) | 0;
      r = SR[i]!;
      ar = dr;
      dr = cr;
      cr = br;
      br = (t << r) | (t >>> (32 - r));
    }
    t = bl;
    bl = br;
    br = t;
    for (let i = 32; i < 48; i++) {
      t = (al + ((bl | ~cl) ^ dl) + x[RL[i]!]! + 0x6ed9eba1) | 0;
      r = SL[i]!;
      al = dl;
      dl = cl;
      cl = bl;
      bl = (t << r) | (t >>> (32 - r));
      t = (ar + ((br & cr) | (~br & dr)) + x[RR[i]!]! + 0x6d703ef3) | 0;
      r = SR[i]!;
      ar = dr;
      dr = cr;
      cr = br;
      br = (t << r) | (t >>> (32 - r));
    }
    t = cl;
    cl = cr;
    cr = t;
    for (let i = 48; i < 64; i++) {
      t = (al + ((bl & dl) | (cl & ~dl)) + x[RL[i]!]! + 0x8f1bbcdc) | 0;
      r = SL[i]!;
      al = dl;
      dl = cl;
      cl = bl;
      bl = (t << r) | (t >>> (32 - r));
      t = (ar + (br ^ cr ^ dr) + x[RR[i]!]!) | 0;
      r = SR[i]!;
      ar = dr;
      dr = cr;
      cr = br;
      br = (t << r) | (t >>> (32 - r));
    }
    t = dl;
    dl = dr;
    dr = t;
    s[0] = (s[0]! + al) | 0;
    s[1] = (s[1]! + bl) | 0;
    s[2] = (s[2]! + cl) | 0;
    s[3] = (s[3]! + dl) | 0;
    s[4] = (s[4]! + ar) | 0;
    s[5] = (s[5]! + br) | 0;
    s[6] = (s[6]! + cr) | 0;
    s[7] = (s[7]! + dr) | 0;
  }
}

/** RIPEMD-320. */
export class Ripemd320Hasher extends MerkleDamgard {
  protected readonly state = new Int32Array([
    0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0, 0x76543210, 0xfedcba98, 0x89abcdef,
    0x01234567, 0x3c2d1e0f,
  ]);

  constructor() {
    super(64, 40, true);
  }

  protected compress(view: DataView, offset: number): void {
    const s = this.state;
    const x = X;
    for (let i = 0; i < 16; i++) x[i] = view.getInt32(offset + i * 4, true);
    let al = s[0]!;
    let bl = s[1]!;
    let cl = s[2]!;
    let dl = s[3]!;
    let el = s[4]!;
    let ar = s[5]!;
    let br = s[6]!;
    let cr = s[7]!;
    let dr = s[8]!;
    let er = s[9]!;
    let t = 0;
    let r = 0;
    for (let i = 0; i < 16; i++) {
      t = (al + (bl ^ cl ^ dl) + x[RL[i]!]!) | 0;
      r = SL[i]!;
      t = (((t << r) | (t >>> (32 - r))) + el) | 0;
      al = el;
      el = dl;
      dl = (cl << 10) | (cl >>> 22);
      cl = bl;
      bl = t;
      t = (ar + (br ^ (cr | ~dr)) + x[RR[i]!]! + 0x50a28be6) | 0;
      r = SR[i]!;
      t = (((t << r) | (t >>> (32 - r))) + er) | 0;
      ar = er;
      er = dr;
      dr = (cr << 10) | (cr >>> 22);
      cr = br;
      br = t;
    }
    t = bl;
    bl = br;
    br = t;
    for (let i = 16; i < 32; i++) {
      t = (al + ((bl & cl) | (~bl & dl)) + x[RL[i]!]! + 0x5a827999) | 0;
      r = SL[i]!;
      t = (((t << r) | (t >>> (32 - r))) + el) | 0;
      al = el;
      el = dl;
      dl = (cl << 10) | (cl >>> 22);
      cl = bl;
      bl = t;
      t = (ar + ((br & dr) | (cr & ~dr)) + x[RR[i]!]! + 0x5c4dd124) | 0;
      r = SR[i]!;
      t = (((t << r) | (t >>> (32 - r))) + er) | 0;
      ar = er;
      er = dr;
      dr = (cr << 10) | (cr >>> 22);
      cr = br;
      br = t;
    }
    t = dl;
    dl = dr;
    dr = t;
    for (let i = 32; i < 48; i++) {
      t = (al + ((bl | ~cl) ^ dl) + x[RL[i]!]! + 0x6ed9eba1) | 0;
      r = SL[i]!;
      t = (((t << r) | (t >>> (32 - r))) + el) | 0;
      al = el;
      el = dl;
      dl = (cl << 10) | (cl >>> 22);
      cl = bl;
      bl = t;
      t = (ar + ((br | ~cr) ^ dr) + x[RR[i]!]! + 0x6d703ef3) | 0;
      r = SR[i]!;
      t = (((t << r) | (t >>> (32 - r))) + er) | 0;
      ar = er;
      er = dr;
      dr = (cr << 10) | (cr >>> 22);
      cr = br;
      br = t;
    }
    t = al;
    al = ar;
    ar = t;
    for (let i = 48; i < 64; i++) {
      t = (al + ((bl & dl) | (cl & ~dl)) + x[RL[i]!]! + 0x8f1bbcdc) | 0;
      r = SL[i]!;
      t = (((t << r) | (t >>> (32 - r))) + el) | 0;
      al = el;
      el = dl;
      dl = (cl << 10) | (cl >>> 22);
      cl = bl;
      bl = t;
      t = (ar + ((br & cr) | (~br & dr)) + x[RR[i]!]! + 0x7a6d76e9) | 0;
      r = SR[i]!;
      t = (((t << r) | (t >>> (32 - r))) + er) | 0;
      ar = er;
      er = dr;
      dr = (cr << 10) | (cr >>> 22);
      cr = br;
      br = t;
    }
    t = cl;
    cl = cr;
    cr = t;
    for (let i = 64; i < 80; i++) {
      t = (al + (bl ^ (cl | ~dl)) + x[RL[i]!]! + 0xa953fd4e) | 0;
      r = SL[i]!;
      t = (((t << r) | (t >>> (32 - r))) + el) | 0;
      al = el;
      el = dl;
      dl = (cl << 10) | (cl >>> 22);
      cl = bl;
      bl = t;
      t = (ar + (br ^ cr ^ dr) + x[RR[i]!]!) | 0;
      r = SR[i]!;
      t = (((t << r) | (t >>> (32 - r))) + er) | 0;
      ar = er;
      er = dr;
      dr = (cr << 10) | (cr >>> 22);
      cr = br;
      br = t;
    }
    t = el;
    el = er;
    er = t;
    s[0] = (s[0]! + al) | 0;
    s[1] = (s[1]! + bl) | 0;
    s[2] = (s[2]! + cl) | 0;
    s[3] = (s[3]! + dl) | 0;
    s[4] = (s[4]! + el) | 0;
    s[5] = (s[5]! + ar) | 0;
    s[6] = (s[6]! + br) | 0;
    s[7] = (s[7]! + cr) | 0;
    s[8] = (s[8]! + dr) | 0;
    s[9] = (s[9]! + er) | 0;
  }
}
