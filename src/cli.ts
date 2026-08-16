#!/usr/bin/env node
import type { Options } from './schemas/options.ts'
import { readFile, writeFile } from 'node:fs/promises'
import process from 'node:process'
import { Command } from 'commander'
import * as yaml from 'yaml'
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

/** Report problems using the flag the user actually typed, not commander's camelCase key. */
function toFlag(optionKey: string): string {
  const kebab = [...optionKey].map(char => (char >= 'A' && char <= 'Z' ? `-${char.toLowerCase()}` : char)).join('')
  return `--${kebab}`
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

export function buildProgram(): Command {
  const program = new Command().name('clash2sing-box').description('Clash to sing-box configuration converter')

  program
    .command('convert')
    .argument('<input...>', 'Input files or http(s) URLs')
    .option('-o, --output <string>', 'Output file path (default: stdout)')
    .option(
      '--outbound-domainresolver-tag <string>',
      'The name of the domain resolver, required for setting resolver strategy',
    )
    .option('--outbound-selector-default <integer>', 'Use the n-th outbound as the default in the selector outbound')
    .option('--outbound-selector-tag <string...>', 'The name(s) of the selector outbound(s)')
    .action(async (inputs: string[], rawOptions: unknown) => {
      const parsed = CliOptions.safeParse(rawOptions)
      if (!parsed.success) {
        const issue = parsed.error.issues[0]
        throw new Error(`${toFlag(String(issue?.path[0] ?? 'option'))} ${issue?.message ?? 'is invalid'}`)
      }
      await convertAction(inputs, parsed.data.output, parsed.data.options)
    })

  return program
}

export async function main(argv: string[]): Promise<number> {
  try {
    await buildProgram().parseAsync(argv)
    return 0
  } catch (error) {
    process.stderr.write(`clash2sing-box: ${errorMessage(error)}\n`)
    return 1
  }
}

if (import.meta.main) {
  process.exitCode = await main(process.argv)
}
