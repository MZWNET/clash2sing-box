import type { Options } from '../src/schemas/options.ts'
import type { SingboxConfig } from '../src/schemas/singbox.ts'
import { convert } from '../src/convert.ts'
import { CliOptions } from '../src/schemas/options.ts'

/** Node names in the shape a subscription checker produces: exit region, then pipe tags. */
function checked(name: string, server = '198.51.100.1'): Record<string, unknown> {
  return { name, type: 'ss', server, port: 8388, cipher: 'aes-256-gcm', password: 'pw' }
}

const hongKong = checked('🇭🇰HK¹⁺_1|12.3MB/s|GPT⁺|YT|NF|0%')
const japan = checked('🇯🇵JP²_1|8.1MB/s|YT-JP')
const unitedStates = checked('🇺🇸US¹-HK⁰_1|3.4MB/s|GPT⁺')

interface Group {
  type: string
  tag: string
  outbounds: string[]
}

function groupsOf(config: SingboxConfig): Group[] {
  return config.outbounds!.filter(
    (outbound): outbound is Group & typeof outbound =>
      'outbounds' in outbound && (outbound.type === 'urltest' || outbound.type === 'selector'),
  )
}

function groupNamed(config: SingboxConfig, tag: string): Group | undefined {
  return groupsOf(config).find(group => group.tag === tag)
}

function withGroups(proxies: Record<string, unknown>[], ...specs: [string, string][]): SingboxConfig {
  const options: Options = {
    outbound: { group: specs.map(([tag, pattern]) => ({ tag, match: new RegExp(pattern) })) },
  }
  return convert({ proxies }, {}, options).config
}

describe('proxy groups', () => {
  it('collects the outbounds whose tag matches, in input order', () => {
    const config = withGroups([hongKong, japan, unitedStates], ['hk', '(?<!-)\\bHK\\b'])

    const group = groupNamed(config, 'hk')
    expect(group).toEqual({ type: 'urltest', tag: 'hk', outbounds: [hongKong['name']] })
  })

  // The whole point of the `(?<!-)` guard: `US¹-HK⁰` names an exit-side CDN location, and
  // `|IN-JP` (from --outbound-entry-geo-db) names an entry. Neither is the node's region.
  it('does not mistake a hyphenated qualifier for the exit region', () => {
    const relay = checked('🇸🇬SG¹-JP⁰_1|5.0MB/s|IN-JP')
    const config = withGroups([japan, relay], ['jp', '(?<!-)\\bJP\\b'])

    expect(groupNamed(config, 'jp')!.outbounds).toEqual([japan['name']])
  })

  it('degrades an unmatched group to a selector aliasing urltest rather than dropping it', () => {
    // Route rules reference groups by tag, so a vanished group breaks `sing-box check`,
    // and sing-box rejects a group with an empty member list.
    const config = withGroups([hongKong], ['netflix', '__nomatch__'])

    expect(groupNamed(config, 'netflix')).toEqual({
      type: 'selector',
      tag: 'netflix',
      outbounds: ['urltest-proxy'],
    })
  })

  it('offers every group in the proxy selector, ahead of the individual nodes', () => {
    const config = withGroups([hongKong, japan], ['hk', '\\bHK\\b'], ['jp', '\\bJP\\b'])

    const selector = groupNamed(config, 'proxy')!
    expect(selector.outbounds.slice(0, 3)).toEqual(['urltest-proxy', 'hk', 'jp'])
  })

  // A group is a race between races, which would distort the latency comparison the same
  // way `direct` would.
  it('keeps groups out of urltest-proxy', () => {
    const config = withGroups([hongKong, japan], ['hk', '\\bHK\\b'])

    expect(groupNamed(config, 'urltest-proxy')!.outbounds).toEqual([hongKong['name'], japan['name']])
  })

  it('emits nothing extra when no group is requested', () => {
    const config = convert({ proxies: [hongKong] }, {}, {}).config

    expect(groupsOf(config).map(group => group.tag)).toEqual(['proxy', 'urltest-proxy'])
  })

  it('matches sing-box outbounds adopted from a sing-box input', () => {
    const options: Options = { outbound: { group: [{ tag: 'self', match: /^anytls-wap/ }] } }
    const config = convert(
      { proxies: [hongKong] },
      { outbounds: [{ type: 'anytls', tag: 'anytls-wap-v4' }] },
      options,
    ).config

    expect(groupNamed(config, 'self')!.outbounds).toEqual(['anytls-wap-v4'])
  })

  it.each([
    ['a node', 'hk', [checked('hk')]],
    ['urltest-proxy', 'urltest-proxy', [hongKong]],
    ['the selector', 'proxy', [hongKong]],
  ])('rejects a group tag colliding with %s', (_what, tag, proxies) => {
    expect(() => withGroups(proxies, [tag, '\\bHK\\b'])).toThrow(`Group tag "${tag}" collides`)
  })

  it('rejects a group tag colliding with a custom selector tag', () => {
    const options: Options = {
      outbound: {
        group: [{ tag: 'streaming', match: /HK/ }],
        selector: { tag: ['streaming'] },
      },
    }
    expect(() => convert({ proxies: [hongKong] }, {}, options)).toThrow('collides')
  })
})

describe('--outbound-group parsing', () => {
  function parse(...entries: string[]): ReturnType<typeof CliOptions.safeParse> {
    return CliOptions.safeParse({ outboundGroup: entries })
  }

  function specs(...entries: string[]): { tag: string; match: RegExp }[] {
    const parsed = parse(...entries)
    expect(parsed.success).toBe(true)
    return parsed.data!.options.outbound.group!
  }

  it('splits on the first "=" so a pattern may contain one', () => {
    const [spec] = specs('ai=GPT(?=⁺)')

    expect(spec!.tag).toBe('ai')
    expect(spec!.match.source).toBe('GPT(?=⁺)')
  })

  // `RegExp.prototype.test` advances `lastIndex` on a /g/ regex, so a reused instance would
  // match every other candidate. Compiling without flags rules that out.
  it('compiles patterns without flags', () => {
    expect(specs('hk=HK')[0]!.match.flags).toBe('')
  })

  it('is undefined when the flag is absent or empty, so convert falls back', () => {
    expect(CliOptions.safeParse({}).data!.options.outbound.group).toBeUndefined()
    expect(CliOptions.safeParse({ outboundGroup: [] }).data!.options.outbound.group).toBeUndefined()
  })

  it.each([
    ['no separator', 'hk'],
    ['an empty tag', '=HK'],
    ['an empty pattern', 'hk='],
  ])('rejects %s', (_what, entry) => {
    const parsed = parse(entry)

    expect(parsed.success).toBe(false)
    expect(parsed.error!.issues[0]!.message).toContain('must look like "tag=regex"')
    expect(parsed.error!.issues[0]!.path[0]).toBe('outboundGroup')
  })

  it('rejects a duplicate tag', () => {
    expect(parse('hk=HK', 'hk=HKG').error!.issues[0]!.message).toContain('was given the tag "hk" twice')
  })

  it('rejects an uncompilable pattern', () => {
    expect(parse('hk=[unterminated').error!.issues[0]!.message).toContain('has an invalid regex')
  })
})
