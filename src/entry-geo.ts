import type { CountryResponse } from 'mmdb-lib'
import { Resolver } from 'node:dns/promises'
import { readFile } from 'node:fs/promises'
import { isIP } from 'node:net'
import { Reader } from 'mmdb-lib'
import { ClashProxyRaw } from './schemas/clash.ts'

/**
 * Resolve a proxy's entry host to a single IP address, or `undefined` if it cannot be
 * resolved.
 */
export type HostResolver = (host: string) => Promise<string | undefined>

/** Map an IP address to an ISO country code, or `undefined` if the database has no answer. */
export type CountryLookup = (address: string) => string | undefined

export interface EntryGeoOptions {
  locate: CountryLookup
  /** Defaults to system DNS. Injectable so tests never touch the network. */
  resolver?: HostResolver
  /** Hosts resolved at once. Sequential lookups over a hundred nodes are painfully slow. */
  concurrency?: number
}

const DEFAULT_CONCURRENCY = 12
const DNS_TIMEOUT_MS = 2000

/**
 * The suffix appended to a node's name, e.g. `|IN-JP`.
 *
 * The hyphen is load-bearing. Region groups are written as `(?<!-)\bJP\b` so that they skip
 * the *exit*-side region qualifiers other tooling appends (`TK-US`, `GM-US`, `-US⁰`); an
 * entry tag formatted the same way is excluded by that same lookbehind, and a node whose
 * traffic enters in Japan but leaves elsewhere stays out of the `jp` group. Change the
 * separator and every region group silently starts collecting entry matches.
 */
function entryTag(countryCode: string): string {
  return `|IN-${countryCode}`
}

/**
 * Load a MaxMind Country database off disk. The only part of this module that does I/O.
 *
 * `registered_country` is a fallback, never a preference. Anycast ranges — Cloudflare's
 * among them, and plenty of entry hosts sit behind those — carry no `country` at all, so
 * without it they go unlabelled. But where both exist they can disagree: an Alibaba Hong
 * Kong address reads `country: HK, registered_country: US`, and HK is the one that
 * describes where the traffic enters.
 */
export function pickCountry(found: CountryResponse | null): string | undefined {
  return found?.country?.iso_code ?? found?.registered_country?.iso_code
}

export async function readCountryDb(path: string): Promise<CountryLookup> {
  const reader = new Reader<CountryResponse>(await readFile(path))
  return address => pickCountry(reader.get(address))
}

/** c-ares rather than `dns.lookup`: it honours a timeout and skips `/etc/hosts`. */
function systemResolver(): HostResolver {
  const resolver = new Resolver({ timeout: DNS_TIMEOUT_MS, tries: 1 })
  return async host => {
    try {
      return (await resolver.resolve4(host))[0]
    } catch {
      try {
        return (await resolver.resolve6(host))[0]
      } catch {
        return undefined
      }
    }
  }
}

/** Run `worker` over `items`, at most `limit` at a time. */
async function forEachLimit<T>(items: T[], limit: number, worker: (item: T) => Promise<void>): Promise<void> {
  let next = 0

  async function drain(): Promise<void> {
    while (next < items.length) {
      await worker(items[next++]!)
    }
  }

  await Promise.all(Array.from({ length: Math.min(limit, items.length) }, async () => drain()))
}

/**
 * Annotate each Clash proxy's name with the country its *entry* address sits in.
 *
 * Subscription checkers rename nodes after the address traffic **exits** from, which is the
 * half you cannot see from the config. The entry — the `server` field — is right there but
 * ungeolocated, and the two differ whenever a node relays. This fills that half in.
 *
 * Mutates `clash.proxies[].name` in place and returns warnings for whatever could not be
 * located. A missing country is never fatal: a node keeps its original name and still
 * converts.
 *
 * Deliberately limited to Clash input. sing-box fragments are hand-written, so their tags
 * are already meaningful, and rewriting them would mean chasing every `detour` and group
 * membership that refers to the old tag.
 */
export async function annotateEntryGeo(clash: unknown, options: EntryGeoOptions): Promise<string[]> {
  const proxies = (clash as { proxies?: unknown } | null)?.proxies
  if (!Array.isArray(proxies) || proxies.length === 0) {
    return []
  }

  const resolve = options.resolver ?? systemResolver()
  const warnings: string[] = []

  /** The `server` of a proxy this can actually annotate, or `undefined`. */
  function entryHost(proxy: unknown): string | undefined {
    const identity = ClashProxyRaw.safeParse(proxy)
    // A proxy without a `server` is one `convert` will skip anyway.
    return identity.success ? identity.data.server : undefined
  }

  // Airports routinely put every node behind one entry hostname, so resolve each host once.
  const hosts = [...new Set(proxies.flatMap(proxy => entryHost(proxy) ?? []))]

  const located = new Map<string, string>()
  await forEachLimit(hosts, options.concurrency ?? DEFAULT_CONCURRENCY, async host => {
    const address = isIP(host) === 0 ? await resolve(host) : host
    if (address === undefined) {
      warnings.push(`Could not resolve entry host "${host}"`)
      return
    }

    const countryCode = options.locate(address)
    if (countryCode === undefined) {
      warnings.push(`No entry country for "${host}" (${address})`)
      return
    }
    located.set(host, countryCode)
  })

  for (const proxy of proxies) {
    const host = entryHost(proxy)
    const countryCode = host === undefined ? undefined : located.get(host)
    if (countryCode !== undefined) {
      const named = proxy as { name: string }
      named.name += entryTag(countryCode)
    }
  }

  return warnings
}
