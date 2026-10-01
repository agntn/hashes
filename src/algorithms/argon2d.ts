import { argon2d, type Argon2Parameters } from "../core/argon2.ts";
import { Argon2 } from "./argon2id.ts";

export class Argon2d extends Argon2 {
  static readonly key = "argon2d";
  protected readonly about = {
    label: "Argon2d",
    description: "Argon2d (RFC 9106), Argon2 with memory reads that follow the data",
    family: "Argon2",
    category: "password",
    securityNote:
      "Its reads follow the data and can leak through a side channel. RFC 9106 fits it to cryptocurrencies and proof of work with no such threat.",
  } as const;

  protected derive(password: Uint8Array, salt: Uint8Array, parameters: Readonly<Argon2Parameters>) {
    return argon2d(password, salt, parameters);
  }
}
