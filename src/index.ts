#!/usr/bin/env node
import type { Options } from './schemas/options.ts'
import { readFile, writeFile } from 'node:fs/promises'
import process from 'node:process'
import { Clerc, defineCommand } from '@clerc/core'
import { friendlyErrorPlugin } from '@clerc/plugin-friendly-error'
import { helpPlugin } from '@clerc/plugin-help'
import { notFoundPlugin } from '@clerc/plugin-not-found'
import { strictFlagsPlugin } from '@clerc/plugin-strict-flags'
import { versionPlugin } from '@clerc/plugin-version'
import * as yaml from 'yaml'
import pkg from '../package.json' with { type: 'json' }
import { convert } from './convert.ts'
import { merge } from './object.ts'
import { ClashConfigProbe } from './schemas/clash.ts'
import { CliOptions } from './schemas/options.ts'
import { SingboxConfigProbe } from './schemas/singbox.ts'

/** `URL.parse` handles casing and malformed input that a prefix test would get wrong. */
export function isHttpUrl(input: string): boolean {
  const url = URL.parse(input)
  return url !== null && (url.protocol === 'http:' || url.protocol === 'https:')
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error)
}

/** Report problems using the flag the user actually typed, not the parser's camelCase key. */
function toFlag(optionKey: string): string {
  return `--${optionKey.replaceAll(/[A-Z]/g, char => `-${char.toLowerCase()}`)}`
}

async function readInput(source: string): Promise<string> {
  if (!isHttpUrl(source)) {
    return readFile(source, 'utf-8')
  }

  const response = await fetch(source, { headers: { 'User-Agent': 'ClashMeta' } })
  // Without this, an error page's HTML gets parsed as a config and fails confusingly.
  if (!response.ok) {
    throw new Error(`Failed to fetch ${source}: ${response.status.toString()} ${response.statusText}`)
  }
  return response.text()
}

/** JSON is tried first: JSON with tab indentation is valid JSON but invalid YAML. */
function parseDocument(content: string, source: string): object {
  let parsed: unknown
  try {
    parsed = JSON.parse(content)
  } catch {
    try {
      parsed = yaml.parse(content)
    } catch (error) {
      throw new Error(`Could not parse ${source} as JSON or YAML: ${errorMessage(error)}`)
    }
  }

  if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
    throw new Error(`${source} does not contain a configuration object`)
  }
  return parsed
}

export interface ClassifiedInputs {
  clash: object[]
  singbox: object[]
}

/**
 * Sort each document into a Clash or a sing-box config. Anything matching neither is an
 * error rather than being silently treated as Clash, which produced an empty config.
 */
export function classifyInputs(documents: { source: string; value: object }[]): ClassifiedInputs {
  const clash: object[] = []
  const singbox: object[] = []

  for (const { source, value } of documents) {
    if (ClashConfigProbe.safeParse(value).success) {
      clash.push(value)
    } else if (SingboxConfigProbe.safeParse(value).success) {
      singbox.push(value)
    } else {
      throw new Error(`${source} is neither a Clash config (needs "proxies") nor a sing-box config`)
    }
  }

  return { clash, singbox }
}

export async function convertAction(inputs: string[], output: string | undefined, options: Options): Promise<void> {
  const documents = await Promise.all(
    inputs.map(async source => ({ source, value: parseDocument(await readInput(source), source) })),
  )

  const { clash, singbox } = classifyInputs(documents)
  const { config, warnings } = convert(merge(...clash), merge(...singbox), options)

  for (const warning of warnings) {
    process.stderr.write(`warning: ${warning}\n`)
  }

  const json = JSON.stringify(config, null, 2)
  if (output === undefined || output === '-' || output === 'stdout') {
    process.stdout.write(`${json}\n`)
  } else {
    await writeFile(output, `${json}\n`)
  }
}

/**
 * The handler goes in as the second argument, never as a `handler` property: `defineCommand`
 * is `(command, handler) => ({ ...command, handler })`, so a property would be overwritten
 * with `undefined` and the command would silently do nothing.
 *
 * clerc types `CommandHandler` as returning `void`, but it does await the result — handlers
 * are dispatched through an emitter that collects their return values into `Promise.all`.
 * The suppression below reads that imprecise type, not the behaviour; without the `await`,
 * `main` would resolve before the output is written.
 */
const convertCommand = defineCommand(
  {
    name: 'convert',
    description: 'Convert Clash and sing-box configurations into one sing-box config',
    parameters: [{ key: '<input...>', description: 'Input files or http(s) URLs' }],
    flags: {
      output: { type: String, short: 'o', description: 'Output file path (default: stdout)' },
      outboundDomainresolverTag: {
        type: String,
        description: 'The name of the domain resolver, required for setting resolver strategy',
      },
      // Deliberately a string: `CliOptions` stays the one place that turns text into a
      // number, so there is a single coercion and a single error message.
      outboundSelectorDefault: {
        type: String,
        description: 'Use the n-th outbound as the default in the selector outbound (integer)',
      },
      outboundSelectorTag: {
        type: [String],
        description: 'The name(s) of the selector outbound(s); repeatable, or comma-separated',
      },
    },
  },
  // oxlint-disable-next-line typescript/no-misused-promises -- see above: clerc awaits this
  async ctx => {
    // Unknown keys — the kebab-case aliases and the plugins' --help/--version — are
    // stripped by the schema, so the whole flag bag goes in as-is.
    const parsed = CliOptions.safeParse(ctx.flags)
    if (!parsed.success) {
      const issue = parsed.error.issues[0]
      throw new Error(`${toFlag(String(issue?.path[0] ?? 'option'))} ${issue?.message ?? 'is invalid'}`)
    }
    await convertAction(ctx.parameters.input, parsed.data.output, parsed.data.options)
  },
)

/**
 * `scriptName` and `version` are not optional: `parse` throws `MissingRequiredMetadataError`
 * without them, and clerc's `name` is not the script name.
 *
 * The return type widens away the per-command generics, which is all `main` needs: it only
 * calls `parse`, declared on the class itself.
 */
function buildCli(): Clerc {
  return (
    Clerc.create({
      name: 'clash2sing-box',
      scriptName: 'clash2sing-box',
      description: 'Clash to sing-box configuration converter',
      version: pkg.version,
    })
      .use(helpPlugin())
      .use(versionPlugin())
      // Rewrites an unmatched command into a message that suggests the closest real one,
      // then rethrows for `friendlyErrorPlugin` to render.
      .use(notFoundPlugin())
      // The default target prints a coloured ` ERROR ` badge through `console.error`. This
      // keeps the `clash2sing-box: ` prefix and routes it through `process.stderr.write`.
      .use(
        friendlyErrorPlugin({
          target: message => process.stderr.write(`clash2sing-box: ${message}\n`),
        }),
      )
      // Registered last so `--help` and `--version` are already known global flags; otherwise
      // strict checking would reject them as unknown.
      .use(strictFlagsPlugin())
      .command(convertCommand)
  )
}

/**
 * Takes an argv that has already been sliced, which is what clerc expects.
 *
 * `friendlyErrorPlugin` owns the error path: it prints the message and calls
 * `process.exit(1)`. The catch below is only a backstop for failures raised outside clerc's
 * error handling, such as a plugin throwing during `setup`. Because of that hard exit, a
 * failing invocation cannot be tested in-process — it would kill the vitest worker rather
 * than fail the test. Error-path tests spawn the CLI as a child process instead.
 */
export async function main(argv: string[]): Promise<number> {
  try {
    await buildCli().parse(argv)
    return 0
  } catch (error) {
    process.stderr.write(`clash2sing-box: ${errorMessage(error)}\n`)
    return 1
  }
}

if (import.meta.main) {
  process.exitCode = await main(process.argv.slice(2))
}
