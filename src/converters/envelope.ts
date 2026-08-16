import type { SingboxAnyEndpoint, SingboxAnyOutbound } from '../schemas/singbox.ts'

/**
 * What a single Clash proxy converts into.
 *
 * Most proxies become exactly one outbound, but two cases do not:
 * - WireGuard becomes an `endpoints` entry, because sing-box removed the WireGuard
 *   outbound in 1.13.0.
 * - ShadowTLS becomes two outbounds, because sing-box models it as a standalone
 *   protocol-agnostic outbound that the inner proxy reaches through `detour`, whereas
 *   Clash folds it into the inner proxy as a plugin.
 */
export interface ConvertedProxy {
  /** The tag proxy groups should reference — never an auxiliary outbound. */
  tag: string
  outbounds: SingboxAnyOutbound[]
  endpoints: SingboxAnyEndpoint[]
}

export function asOutbound(outbound: SingboxAnyOutbound): ConvertedProxy {
  return { tag: outbound.tag, outbounds: [outbound], endpoints: [] }
}

/** The type of the outbound or endpoint that `tag` refers to. */
export function primaryType(proxy: ConvertedProxy): string | undefined {
  return proxy.outbounds[0]?.type ?? proxy.endpoints[0]?.type
}

export function asEndpoint(endpoint: SingboxAnyEndpoint): ConvertedProxy {
  return { tag: endpoint.tag, outbounds: [], endpoints: [endpoint] }
}

/**
 * A primary outbound plus the plumbing it depends on. Only the primary is referenced by
 * proxy groups: selecting a bare ShadowTLS shell would give you a tunnel with nothing
 * inside it.
 */
export function asChain(primary: SingboxAnyOutbound, ...auxiliary: SingboxAnyOutbound[]): ConvertedProxy {
  return { tag: primary.tag, outbounds: [primary, ...auxiliary], endpoints: [] }
}
