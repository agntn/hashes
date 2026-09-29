import { existsSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { stripVTControlCharacters } from "node:util";

import type { ExtensionAPI, Theme } from "@oh-my-pi/pi-coding-agent";
import { Text } from "@oh-my-pi/pi-coding-agent";

import type * as HashTools from "../../../dist/tool-operations.d.mts";
import {
  HASH_FAMILIES,
  MAX_ALGORITHM_LENGTH,
  MAX_EXPECTED_LENGTH,
  MAX_INPUT_LENGTH,
  MAX_KEY_LENGTH,
  MAX_PARAMETER_LENGTH,
  MAX_PARAMETERS,
  PARAMETER_NAME_PATTERN,
  PARAMETER_DESCRIPTIONS,
  SALT_PATTERN,
  TEXT_ENCODINGS,
  INPUT_ENCODINGS,
  TOOL_DESCRIPTIONS,
  TOOL_TITLES,
} from "../../shared/tool-contract.ts";

const sourceModulePath = fileURLToPath(new URL("../../../src/tool-operations.ts", import.meta.url));
let toolOperationsPromise: Promise<typeof HashTools> | undefined;

/**
 * Loads the tool executors shared with the MCP server and the Pi extension, so the tool answers
 * stay identical across surfaces. Both specifiers stay literal on purpose: OMP's compiled loader
 * rewrites bare dependencies only for imports it can see statically.
 *
 * @returns {Promise<typeof HashTools>} Shared tool operations module.
 */
function loadToolOperations(): Promise<typeof HashTools> {
  toolOperationsPromise ??= (
    existsSync(sourceModulePath)
      ? import("../../../src/tool-operations.ts")
      : import("../../../dist/tool-operations.mjs")
  ) as Promise<typeof HashTools>;

  return toolOperationsPromise;
}

// Renderer interpolations cross the terminal trust boundary: model arguments and
// external values may carry ANSI/OSC escape sequences or raw C0/C1 control bytes
// that OMP's Text component passes through to the terminal unchanged, and U+2028/U+2029 break
// a line in terminals that honour them. String()
// first, because hostile JSON is not bound by the declared parameter types.
export function sanitizeTerminalText(value: unknown): string {
  return stripVTControlCharacters(String(value))
    .replaceAll(/[\u0000-\u001F\u007F-\u009F\u2028\u2029]/g, " ")
    .replaceAll(/ +/g, " ")
    .trim();
}

/** The part of the host theme the status lines draw with. */
interface StatusTheme {
  readonly fg: Theme["fg"];
  readonly styledSymbol: Theme["styledSymbol"];
  readonly spinnerFrames: readonly string[];
  readonly format: Readonly<{ bracketLeft: string; bracketRight: string }>;
}

/** Longest input preview a status line shows. */
const PREVIEW_LENGTH = 40;

/**
 * Shortens a value for a status line after sanitizing it.
 *
 * @param value - Any argument value.
 * @returns {string} The clean value, cut to `PREVIEW_LENGTH` characters.
 */
export function preview(value: unknown): string {
  const clean = sanitizeTerminalText(value);
  return clean.length > PREVIEW_LENGTH ? `${clean.slice(0, PREVIEW_LENGTH - 1)}…` : clean;
}

/**
 * Draws the call status line: the spinner or done mark, the tool title and a short description.
 *
 * @param title - Tool label.
 * @param description - Sanitized description of the call.
 * @param options - Render options from the host.
 * @param options.isPartial - Whether the call is still running.
 * @param options.spinnerFrame - Spinner frame, when the host animates one.
 * @param theme - Host theme.
 * @returns {Text} The status line.
 */
function callLine(
  title: string,
  description: string,
  options: Readonly<{ isPartial: boolean; spinnerFrame?: number }>,
  theme: StatusTheme,
): Text {
  const icon = options.isPartial
    ? options.spinnerFrame === undefined
      ? theme.styledSymbol("status.pending", "muted")
      : (theme.spinnerFrames[options.spinnerFrame % theme.spinnerFrames.length] ??
        theme.styledSymbol("status.running", "accent"))
    : theme.styledSymbol("status.done", "success");
  const label = theme.fg("accent", title);
  return new Text(
    `${icon} ${label}${description ? `: ${theme.fg("muted", description)}` : ""}`,
    0,
    0,
  );
}

/**
 * Draws the result line: success or error mark, tool title, read badge and a short summary.
 *
 * @param title - Tool label.
 * @param result - Tool result from the host.
 * @param summary - Sanitized summary of the details, or an empty string.
 * @param theme - Host theme.
 * @returns {Text} The result line.
 */
function resultLine(
  title: string,
  result: Readonly<{ isError?: boolean }>,
  summary: string,
  theme: StatusTheme,
): Text {
  const icon = result.isError
    ? theme.styledSymbol("status.error", "error")
    : theme.styledSymbol("status.done", "success");
  const { bracketLeft, bracketRight } = theme.format;
  const badge = theme.fg("accent", `${bracketLeft}read${bracketRight}`);
  const meta = !result.isError && summary ? ` ${theme.fg("dim", summary)}` : "";
  return new Text(`${icon} ${theme.fg("accent", title)} ${badge}${meta}`, 0, 0);
}

/**
 * Summarizes a digest result: the algorithm and the digest.
 *
 * @param details - Result details.
 * @returns {string} The summary, or an empty string without a digest.
 */
function digestSummary(details: unknown): string {
  if (typeof details !== "object" || details === null || !("digest" in details)) return "";
  const { algorithm, digest } = details as { algorithm?: unknown; digest?: unknown };
  return `${sanitizeTerminalText(algorithm)} ${preview(digest)}`;
}

export default function hashesExtension(pi: ExtensionAPI): void {
  // OMP validates tool parameters with its own TypeBox build, so schemas must come from the
  // host-injected facade rather than the shared TypeBox schemas the Pi extension uses.
  const { Type } = pi.typebox;
  const d = PARAMETER_DESCRIPTIONS;
  const closed = { additionalProperties: false } as const;
  const algorithm = Type.String({
    minLength: 1,
    maxLength: MAX_ALGORITHM_LENGTH,
    description: d.algorithm,
  });
  const input = Type.String({
    maxLength: MAX_INPUT_LENGTH,
    description: d.input,
  });
  const inputEncoding = Type.Optional(Type.Enum(INPUT_ENCODINGS, { description: d.inputEncoding }));
  const encoding = Type.Optional(Type.Enum(TEXT_ENCODINGS, { description: d.encoding }));
  const salt = Type.Optional(
    Type.String({
      pattern: SALT_PATTERN,
      description: d.salt,
    }),
  );
  const parameters = Type.Optional(
    Type.Record(
      Type.String({ pattern: PARAMETER_NAME_PATTERN }),
      Type.Union([Type.Integer(), Type.String({ maxLength: MAX_PARAMETER_LENGTH })]),
      { maxProperties: MAX_PARAMETERS, additionalProperties: false, description: d.parameters },
    ),
  );
  pi.setLabel("Hashes");

  pi.registerTool({
    name: "hash_compute",
    label: TOOL_TITLES.hash_compute,
    description: TOOL_DESCRIPTIONS.hash_compute,
    parameters: Type.Object(
      { algorithm, input, inputEncoding, encoding, salt, parameters },
      closed,
    ),
    approval: "read",
    async execute(_toolCallId, params) {
      return (await loadToolOperations()).hashCompute(params);
    },
    renderCall: (args, options, theme) =>
      callLine(
        TOOL_TITLES.hash_compute,
        `${sanitizeTerminalText(args.algorithm)} ${preview(args.input)}`,
        options,
        theme,
      ),
    renderResult: (result, _options, theme) =>
      resultLine(TOOL_TITLES.hash_compute, result, digestSummary(result.details), theme),
  });

  pi.registerTool({
    name: "hash_hmac",
    label: TOOL_TITLES.hash_hmac,
    description: TOOL_DESCRIPTIONS.hash_hmac,
    parameters: Type.Object(
      {
        algorithm: Type.String({
          minLength: 1,
          maxLength: MAX_ALGORITHM_LENGTH,
          description: d.hmacAlgorithm,
        }),
        input,
        inputEncoding,
        key: Type.String({ maxLength: MAX_KEY_LENGTH, description: d.key }),
        encoding,
      },
      closed,
    ),
    approval: "read",
    async execute(_toolCallId, params) {
      return (await loadToolOperations()).hashHmac(params);
    },
    // The key stays off the terminal.
    renderCall: (args, options, theme) =>
      callLine(
        TOOL_TITLES.hash_hmac,
        `${sanitizeTerminalText(args.algorithm)} ${preview(args.input)}`,
        options,
        theme,
      ),
    renderResult: (result, _options, theme) =>
      resultLine(TOOL_TITLES.hash_hmac, result, digestSummary(result.details), theme),
  });

  pi.registerTool({
    name: "hash_verify",
    label: TOOL_TITLES.hash_verify,
    description: TOOL_DESCRIPTIONS.hash_verify,
    parameters: Type.Object(
      {
        algorithm,
        input,
        inputEncoding,
        expected: Type.String({
          minLength: 1,
          maxLength: MAX_EXPECTED_LENGTH,
          description: d.expected,
        }),
        encoding: Type.Optional(Type.Enum(TEXT_ENCODINGS, { description: d.expectedEncoding })),
        salt: Type.Optional(Type.String({ pattern: SALT_PATTERN, description: d.verifySalt })),
        parameters,
      },
      closed,
    ),
    approval: "read",
    async execute(_toolCallId, params) {
      return (await loadToolOperations()).hashVerify(params);
    },
    renderCall: (args, options, theme) =>
      callLine(
        TOOL_TITLES.hash_verify,
        `${sanitizeTerminalText(args.algorithm)} ${preview(args.input)}`,
        options,
        theme,
      ),
    renderResult: (result, _options, theme) => {
      const details = result.details as { match?: unknown } | undefined;
      const summary = details && "match" in details ? (details.match ? "match" : "mismatch") : "";
      return resultLine(TOOL_TITLES.hash_verify, result, summary, theme);
    },
  });

  pi.registerTool({
    name: "hash_algorithms",
    label: TOOL_TITLES.hash_algorithms,
    description: TOOL_DESCRIPTIONS.hash_algorithms,
    parameters: Type.Object(
      {
        family: Type.Optional(Type.Enum(HASH_FAMILIES, { description: d.family })),
        algorithm: Type.Optional(
          Type.String({
            minLength: 1,
            maxLength: MAX_ALGORITHM_LENGTH,
            description: d.describe,
          }),
        ),
      },
      closed,
    ),
    approval: "read",
    async execute(_toolCallId, params) {
      return (await loadToolOperations()).hashAlgorithms(params);
    },
    renderCall: (args, options, theme) =>
      callLine(
        TOOL_TITLES.hash_algorithms,
        sanitizeTerminalText(args.algorithm ?? args.family ?? ""),
        options,
        theme,
      ),
    renderResult: (result, _options, theme) => {
      const details = result.details as { algorithms?: unknown } | undefined;
      const count = Array.isArray(details?.algorithms) ? details.algorithms.length : undefined;
      return resultLine(
        TOOL_TITLES.hash_algorithms,
        result,
        count === undefined ? "" : `${count} algorithms`,
        theme,
      );
    },
  });
}
