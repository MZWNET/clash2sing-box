import type { Options } from '../src/schemas/options.ts'
import type { SingboxConfig } from '../src/schemas/singbox.ts'
import { convert } from '../src/convert.ts'
import { CliOptions } from '../src/schemas/options.ts'

const proxy = { name: 'ss-01', type: 'ss', server: '1.2.3.4', port: 8388, cipher: 'aes-256-gcm', password: 'pw' }
const warpEndpoint = { outbounds: [], endpoints: [{ type: 'wireguard', tag: 'warp' }] }

function group(config: SingboxConfig, tag: string): { outbounds: string[] } {
  return config.outbounds!.find(outbound => outbound.tag === tag) as unknown as { outbounds: string[] }
}

describe('--outbound-no-urltest', () => {
  const options: Options = { outbound: { noUrltest: ['warp'] } }

  it('keeps an excluded tag selectable but out of the race', () => {
    const { config, warnings } = convert({ proxies: [proxy] }, warpEndpoint, options)

    expect(group(config, 'proxy').outbounds).toContain('warp')
    expect(group(config, 'urltest-proxy').outbounds).not.toContain('warp')
    expect(group(config, 'urltest-proxy').outbounds).toContain('ss-01')
    expect(warnings).toEqual([])
  })

  // Without the flag a WireGuard endpoint races like any other outbound, which is the
  // behaviour every other conversion depends on.
  it('races it by default', () => {
    const { config } = convert({ proxies: [proxy] }, warpEndpoint, {})

    expect(group(config, 'urltest-proxy').outbounds).toContain('warp')
  })

  // "Not latency-testable" is a property of the outbound, so a named group honours it too.
  it('excludes it from a named group as well', () => {
    const { config } = convert({ proxies: [proxy] }, warpEndpoint, {
      outbound: { ...options.outbound, group: [{ tag: 'cf', match: /warp|ss/ }] },
    })

    expect(group(config, 'cf').outbounds).toEqual(['ss-01'])
  })

  it('degrades a group left empty by the exclusion', () => {
    const { config } = convert({ proxies: [proxy] }, warpEndpoint, {
      outbound: { ...options.outbound, group: [{ tag: 'cf', match: /warp/ }] },
    })

    expect(group(config, 'cf').outbounds).toEqual(['urltest-proxy'])
  })

  // A typo would otherwise be invisible: the tag simply never matches anything.
  it('warns about a tag that names no outbound', () => {
    const { warnings } = convert({ proxies: [proxy] }, {}, { outbound: { noUrltest: ['wrap'] } })

    expect(warnings).toEqual(['No outbound named "wrap" to exclude from URLTest'])
  })

  it('parses repeated and comma-separated occurrences alike', () => {
    const commas = CliOptions.safeParse({ outboundNoUrltest: ['warp,relay'] })
    const repeats = CliOptions.safeParse({ outboundNoUrltest: ['warp', 'relay'] })

    expect(commas.data!.options.outbound.noUrltest).toEqual(['warp', 'relay'])
    expect(repeats.data!.options.outbound.noUrltest).toEqual(['warp', 'relay'])
  })

  it('is undefined when absent or empty, so convert falls back', () => {
    expect(CliOptions.safeParse({}).data!.options.outbound.noUrltest).toBeUndefined()
    expect(CliOptions.safeParse({ outboundNoUrltest: [] }).data!.options.outbound.noUrltest).toBeUndefined()
  })
})
