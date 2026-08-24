import type { ConvertedProxy } from './converters/envelope.ts'
import type { Options } from './schemas/options.ts'
import type {
  SingboxAnyEndpoint,
  SingboxAnyOutbound,
  SingboxConfig,
  SingboxOutboundURLTest,
} from './schemas/singbox.ts'
import type { z } from 'zod'
import { primaryType } from './converters/envelope.ts'
import { ProxyToOutbound } from './converters/index.ts'
import { VLESS_FLOW } from './converters/vless.ts'
import { merge, omitUndefined } from './object.ts'
import { Clash, ClashProxyRaw } from './schemas/clash.ts'
import { SingboxConfigSchema, SingboxOutboundSelector, SingboxTaggedOutbound } from './schemas/singbox.ts'

type ClashProxyIdentity = z.infer<typeof ClashProxyRaw>

export interface ConvertResult {
  config: SingboxConfig
  /** Non-fatal problems: skipped proxies, normalized values. Never written to the console. */
  warnings: string[]
}

const IP_VERSION_STRATEGY = {
  dual: undefined,
  ipv4: 'ipv4_only',
  ipv6: 'ipv6_only',
  'ipv4-prefer': 'prefer_ipv4',
  'ipv6-prefer': 'prefer_ipv6',
} as const

/**
 * URLTest picks the lowest-latency member, so including these would defeat it: `direct`
 * always wins the race, and `block` always fails it. They stay selectable by hand.
 */
const NOT_LATENCY_TESTABLE = new Set(['direct', 'block'])

export function convert(clashInput: unknown, singboxInput: unknown = {}, options: Options = {}): ConvertResult {
  const warnings: string[] = []
  const allOutbounds: SingboxAnyOutbound[] = []
  const allEndpoints: SingboxAnyEndpoint[] = []
  /** Only these are offered in proxy groups — auxiliary outbounds are plumbing. */
  const selectableTags: string[] = []
  /** The subset of the above worth racing in URLTest. */
  const testableTags: string[] = []

  /** Offer a tag to the proxy groups, keeping it out of URLTest if it would skew the race. */
  function offer(tag: string, type: string | undefined): void {
    selectableTags.push(tag)
    if (!NOT_LATENCY_TESTABLE.has(type ?? '')) {
      testableTags.push(tag)
    }
  }

  /**
   * Adopt entries the sing-box input already carried. They pass through untouched — a
   * string `tag` is all the groups need in order to reference them.
   */
  function adopt<T extends { tag: string; type: string }>(entries: unknown[], kind: string, sink: T[]): void {
    for (const [index, entry] of entries.entries()) {
      if (!SingboxTaggedOutbound.safeParse(entry).success) {
        warnings.push(`Skipping sing-box ${kind} at index ${index.toString()}: missing a string "tag"`)
        continue
      }

      const adopted = entry as T
      sink.push(adopted)
      offer(adopted.tag, adopted.type)
    }
  }

  // 1. Convert Clash proxies, skipping (never aborting on) anything unusable.
  const clash = Clash.safeParse(clashInput)
  const proxies = clash.success ? (clash.data.proxies ?? []) : []
  for (const [index, entry] of proxies.entries()) {
    const identity = ClashProxyRaw.safeParse(entry)
    if (!identity.success) {
      warnings.push(`Skipping proxy at index ${index.toString()}: ${firstIssue(identity.error)}`)
      continue
    }

    const proxy = identity.data
    const converted = ProxyToOutbound.safeParse(entry)
    if (!converted.success) {
      warnings.push(`Skipping proxy "${proxy.name}" (type: ${proxy.type}): ${firstIssue(converted.error)}`)
      continue
    }

    if (proxy.type === 'vless' && proxy.flow !== undefined && proxy.flow !== VLESS_FLOW) {
      warnings.push(`Normalized VLESS flow "${proxy.flow}" to "${VLESS_FLOW}" for proxy "${proxy.name}"`)
    }

    const envelope: ConvertedProxy = converted.data
    applyDomainResolver(envelope, proxy, options)
    allOutbounds.push(...envelope.outbounds)
    allEndpoints.push(...envelope.endpoints)
    offer(envelope.tag, primaryType(envelope))
  }

  // 2. Carry over outbounds and endpoints supplied by the sing-box input.
  const singbox = SingboxConfigSchema.safeParse(singboxInput)
  const {
    outbounds: providedOutbounds = [],
    endpoints: providedEndpoints = [],
    ...restOfSingboxInput
  } = singbox.success ? singbox.data : {}

  adopt(providedOutbounds, 'outbound', allOutbounds)
  adopt(providedEndpoints, 'endpoint', allEndpoints)

  // 3. Build the group outbounds.
  const urltest: z.infer<typeof SingboxOutboundURLTest> = {
    type: 'urltest',
    tag: 'urltest-proxy',
    // Falling back keeps a direct-only config from producing an empty URLTest group.
    outbounds: testableTags.length > 0 ? testableTags : selectableTags,
  }

  const selectorTemplate: z.infer<typeof SingboxOutboundSelector> = {
    type: 'selector',
    tag: 'proxy',
    outbounds: [urltest.tag, ...selectableTags],
    default: urltest.tag,
  }

  const selectorDefault = options.outbound?.selector?.default
  if (selectorDefault !== undefined) {
    const target = selectableTags.at(selectorDefault)
    if (target === undefined) {
      throw new Error(
        `Invalid outbound ordinal number ${selectorDefault.toString()}: there are ${selectableTags.length.toString()} outbound(s)`,
      )
    }
    selectorTemplate.default = target
  }

  const selectorTags = options.outbound?.selector?.tag ?? [selectorTemplate.tag]
  const selectors = selectorTags.map(tag => SingboxOutboundSelector.parse({ ...selectorTemplate, tag }))

  // 4. Merge with everything else the sing-box input carried (dns, log, route, …).
  const generated: SingboxConfig = { outbounds: [...selectors, urltest, ...allOutbounds] }
  // Only emitted when WireGuard is actually in play, so ordinary configs stay unchanged.
  if (allEndpoints.length > 0) {
    generated.endpoints = allEndpoints
  }

  return { config: merge(generated, restOfSingboxInput), warnings }
}

/**
 * `ip-version` maps onto a per-outbound resolver strategy, but only once the caller has
 * named a resolver. Applied to whichever entries actually carry a server address.
 */
function applyDomainResolver(envelope: ConvertedProxy, proxy: ClashProxyIdentity, options: Options): void {
  const resolverTag = options.outbound?.domainresolver?.tag
  const ipVersion = proxy['ip-version']
  if (ipVersion === undefined || resolverTag === undefined) {
    return
  }

  const domainResolver = omitUndefined({ server: resolverTag, strategy: IP_VERSION_STRATEGY[ipVersion] })
  for (const entry of [...envelope.outbounds, ...envelope.endpoints]) {
    if ('server' in entry && entry.server !== undefined) {
      entry.domain_resolver = domainResolver
    }
  }
}

function firstIssue(error: z.ZodError): string {
  const issue = error.issues[0]
  if (issue === undefined) {
    return 'invalid proxy'
  }
  return issue.path.length > 0 ? `${issue.path.join('.')}: ${issue.message}` : issue.message
}
