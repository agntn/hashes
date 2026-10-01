import { argon2i, type Argon2Parameters } from "../core/argon2.ts";
import { Argon2 } from "./argon2id.ts";

export class Argon2i extends Argon2 {
  static readonly key = "argon2i";
  protected readonly about = {
    label: "Argon2i",
    description: "Argon2i (RFC 9106), Argon2 with memory reads that never depend on the password",
    family: "Argon2",
    category: "password",
    securityNote:
      "Its reads leak nothing to a side channel, but it needs more passes against time-memory trade-offs. RFC 9106 makes argon2id the primary variant.",
  } as const;

  protected derive(password: Uint8Array, salt: Uint8Array, parameters: Readonly<Argon2Parameters>) {
    return argon2i(password, salt, parameters);
  }
}
