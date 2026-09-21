import type { CountryLookup, HostResolver } from '../src/entry-geo.ts'
import { annotateEntryGeo, pickCountry } from '../src/entry-geo.ts'

function proxy(name: string, server: string): Record<string, unknown> {
  return { name, type: 'ss', server, port: 8388, cipher: 'aes-256-gcm', password: 'pw' }
}

/** A stand-in for the mmdb reader; anything unlisted has no answer, as in a real database. */
function locateFrom(table: Record<string, string>): CountryLookup {
  return address => table[address]
}

function resolveFrom(table: Record<string, string>): HostResolver {
  return async host => table[host]
}

const locate = locateFrom({ '203.0.113.7': 'JP', '198.51.100.9': 'HK', '2001:db8::1': 'SG' })

// Shapes taken from a real GeoLite2-Country lookup.
describe('pickCountry()', () => {
  it('prefers country over registered_country where they disagree', () => {
    // 47.242.66.10, an Alibaba Hong Kong address: HK is where traffic enters, US is only
    // where the range is registered.
    expect(pickCountry({ country: { iso_code: 'HK' }, registered_country: { iso_code: 'US' } } as never)).toBe('HK')
  })

  it('falls back to registered_country when there is no country', () => {
    // Anycast ranges carry no `country` — 104.16.132.229 (Cloudflare) is registered US,
    // and plenty of entry hosts sit behind those.
    expect(pickCountry({ registered_country: { iso_code: 'US' } } as never)).toBe('US')
  })

  it.each([
    ['a miss', null],
    ['a record with neither', {}],
  ])('returns undefined for %s', (_what, found) => {
    expect(pickCountry(found as never)).toBeUndefined()
  })
})

describe('annotateEntryGeo()', () => {
  it('appends the entry country to a proxy whose server is a literal IP', async () => {
    const clash = { proxies: [proxy('🇺🇸US¹⁺_1|5.0MB/s', '203.0.113.7')] }
    const warnings = await annotateEntryGeo(clash, { locate })

    expect(clash.proxies[0]!['name']).toBe('🇺🇸US¹⁺_1|5.0MB/s|IN-JP')
    expect(warnings).toEqual([])
  })

  it('resolves a hostname before the lookup', async () => {
    const clash = { proxies: [proxy('node-1', 'relay.example.com')] }
    const warnings = await annotateEntryGeo(clash, {
      locate,
      resolver: resolveFrom({ 'relay.example.com': '198.51.100.9' }),
    })

    expect(clash.proxies[0]!['name']).toBe('node-1|IN-HK')
    expect(warnings).toEqual([])
  })

  it('handles an IPv6 server without resolving it', async () => {
    const clash = { proxies: [proxy('node-v6', '2001:db8::1')] }
    const resolver = vi.fn<HostResolver>()
    await annotateEntryGeo(clash, { locate, resolver })

    expect(clash.proxies[0]!['name']).toBe('node-v6|IN-SG')
    expect(resolver).not.toHaveBeenCalled()
  })

  // Airports routinely put a whole subscription behind one entry hostname.
  it('resolves each distinct host once', async () => {
    const resolver = vi.fn<HostResolver>(async () => '203.0.113.7')
    const clash = {
      proxies: [proxy('a', 'relay.example.com'), proxy('b', 'relay.example.com'), proxy('c', 'other.example.com')],
    }
    await annotateEntryGeo(clash, { locate, resolver })

    expect(resolver).toHaveBeenCalledTimes(2)
    expect(clash.proxies.map(entry => entry['name'])).toEqual(['a|IN-JP', 'b|IN-JP', 'c|IN-JP'])
  })

  it('leaves a node alone and warns when DNS fails', async () => {
    const clash = { proxies: [proxy('unresolvable', 'nope.example.com'), proxy('fine', '203.0.113.7')] }
    const warnings = await annotateEntryGeo(clash, { locate, resolver: resolveFrom({}) })

    expect(clash.proxies.map(entry => entry['name'])).toEqual(['unresolvable', 'fine|IN-JP'])
    expect(warnings).toEqual(['Could not resolve entry host "nope.example.com"'])
  })

  it('leaves a node alone and warns when the database has no country', async () => {
    const clash = { proxies: [proxy('private', '10.0.0.1')] }
    const warnings = await annotateEntryGeo(clash, { locate })

    expect(clash.proxies[0]!['name']).toBe('private')
    expect(warnings).toEqual(['No entry country for "10.0.0.1" (10.0.0.1)'])
  })

  it('skips an entry that is not an identifiable proxy', async () => {
    const clash = { proxies: [{ server: '203.0.113.7' }, proxy('good', '203.0.113.7')] }
    const warnings = await annotateEntryGeo(clash, { locate })

    expect(clash.proxies[1]!['name']).toBe('good|IN-JP')
    expect(warnings).toEqual([])
  })

  it.each([
    ['no proxies key', {}],
    ['an empty list', { proxies: [] }],
    ['a non-Clash document', { outbounds: [] }],
    ['null', null],
  ])('does nothing for %s', async (_what, clash) => {
    const locateSpy = vi.fn<CountryLookup>()
    expect(await annotateEntryGeo(clash, { locate: locateSpy })).toEqual([])
    expect(locateSpy).not.toHaveBeenCalled()
  })

  it('visits every host when there are more of them than the concurrency limit', async () => {
    const clash = {
      proxies: Array.from({ length: 25 }, (_, index) => proxy(`n${index.toString()}`, `h${index.toString()}`)),
    }
    const warnings = await annotateEntryGeo(clash, { locate, resolver: resolveFrom({}), concurrency: 4 })

    expect(warnings).toHaveLength(25)
  })
})
