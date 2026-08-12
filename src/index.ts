import type { Options } from './libs/utils.ts'
import { readFileSync, writeFileSync } from 'node:fs'
import process from 'node:process'
import { Command } from 'commander'
import * as yaml from 'yaml'
import { convert, merge } from './libs/utils.ts'

const HTTP_URL_PATTERN = /^https?:\/\//

export async function convertAction(options: Options & { output?: string }, ...input: string[]): Promise<void> {
  const clashConfigInputs: object[] = []
  const singboxConfigInputs: object[] = []

  await Promise.all(
    input.map(async i => {
      const content = HTTP_URL_PATTERN.test(i)
        ? await (await fetch(i, { headers: { 'User-Agent': 'ClashMeta' } })).text()
        : readFileSync(i, 'utf-8')

      try {
        const jsonContent: unknown = JSON.parse(content)
        if (
          typeof jsonContent === 'object' &&
          jsonContent !== null &&
          ('log' in jsonContent ||
            'dns' in jsonContent ||
            'inbounds' in jsonContent ||
            'outbounds' in jsonContent ||
            'route' in jsonContent)
        ) {
          singboxConfigInputs.push(jsonContent)
          return
        }
        // If it's valid JSON but not a sing-box config, treat it as Clash (JSON is a subset of YAML)
        clashConfigInputs.push(jsonContent as object)
      } catch {
        // Not JSON, assume YAML and try to parse.
        clashConfigInputs.push(yaml.parse(content) as object)
      }
    }),
  )

  const mergedClash = merge(...clashConfigInputs)
  const mergedSingbox = merge(...singboxConfigInputs)

  const finalConfigJson = convert(mergedClash, mergedSingbox, options)

  if (options.output === undefined || options.output === '-' || options.output === 'stdout') {
    process.stdout.write(`${finalConfigJson}\n`)
  } else {
    writeFileSync(options.output, finalConfigJson)
  }
}

const program = new Command().name('clash2sing-box').description('Clash to sing-box configuration converter')

program
  .command('convert')
  .argument('<input...>', 'Input files')
  .option('-o, --output <string>', 'Output file path')
  .option(
    '--outbound-domainresolver-tag <string>',
    'The name of the domain resolver, required for setting resolver strategy',
  )
  .option('--outbound-selector-default <integer>', 'Use the n-th outbound as the default in the selector outbound')
  .option('--outbound-selector-tag <string...>', 'The name(s) of the selector outbound(s)')
  .action((input: string[], options: Record<string, unknown>) => {
    const opts: Options & { output?: string } = {
      output: options['output'] as string | undefined,
    }
    if (
      options['outboundDomainresolverTag'] !== undefined ||
      options['outboundSelectorDefault'] !== undefined ||
      options['outboundSelectorTag'] !== undefined
    ) {
      opts.outbound = {}
      if (options['outboundDomainresolverTag'] !== undefined) {
        opts.outbound.domainresolver = { tag: options['outboundDomainresolverTag'] as string }
      }
      if (options['outboundSelectorDefault'] !== undefined || options['outboundSelectorTag'] !== undefined) {
        opts.outbound.selector = {}
        if (options['outboundSelectorDefault'] !== undefined) {
          opts.outbound.selector.default = Number(options['outboundSelectorDefault'])
        }
        if (options['outboundSelectorTag'] !== undefined) {
          opts.outbound.selector.tag = options['outboundSelectorTag'] as string[]
        }
      }
    }
    void convertAction(opts, ...input)
  })

program.parse(process.argv)
