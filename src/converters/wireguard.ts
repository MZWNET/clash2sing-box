import { Buffer } from 'node:buffer'
import { z } from 'zod'
import { omitUndefined } from '../object.ts'
import { ClashProxyWireGuard } from '../schemas/clash.ts'
import { SingboxEndpointWireGuard } from '../schemas/singbox.ts'
import { convertDialFields } from './shared.ts'

type WireGuardProxy = z.infer<typeof ClashProxyWireGuard>
type WireGuardEndpoint = z.input<typeof SingboxEndpointWireGuard>
type WireGuardPeer = NonNullable<WireGuardEndpoint['peers']>[number]

/** Routing everything through the tunnel is mihomo's effective default. */
const DEFAULT_ALLOWED_IPS = ['0.0.0.0/0', '::/0']

/** sing-box wants CIDR; mihomo often gives a bare address. */
function toPrefix(address: string, bits: string): string {
  return address.includes('/') ? address : `${address}/${bits}`
}

/** mihomo accepts `reserved` either as three bytes or as a base64 string. */
function toReserved(reserved: number[] | string | undefined): number[] | undefined {
  if (reserved === undefined) {
    return undefined
  }
  if (Array.isArray(reserved)) {
    return reserved
  }
  const bytes = [...Buffer.from(reserved, 'base64')]
  return bytes.length === 0 ? undefined : bytes
}

function buildPeers(proxy: WireGuardProxy): WireGuardPeer[] {
  if (proxy.peers !== undefined && proxy.peers.length > 0) {
    return proxy.peers.map(peer =>
      omitUndefined({
        address: peer.server,
        port: peer.port,
        public_key: peer['public-key'],
        pre_shared_key: peer['pre-shared-key'],
        allowed_ips: peer['allowed-ips'] ?? DEFAULT_ALLOWED_IPS,
        reserved: toReserved(peer.reserved),
      }),
    )
  }

  // Single-peer form: the peer fields sit at the top level.
  if (proxy['public-key'] === undefined) {
    return []
  }
  return [
    omitUndefined({
      address: proxy.server,
      port: proxy.port,
      public_key: proxy['public-key'],
      pre_shared_key: proxy['pre-shared-key'],
      allowed_ips: proxy['allowed-ips'] ?? DEFAULT_ALLOWED_IPS,
      persistent_keepalive_interval: proxy['persistent-keepalive'],
      reserved: toReserved(proxy.reserved),
    }),
  ]
}

/**
 * WireGuard converts to a top-level `endpoints` entry, not an outbound: sing-box
 * deprecated the WireGuard outbound in 1.11.0 and removed it in 1.13.0.
 */
export const WireGuardPipeline = ClashProxyWireGuard.transform((proxy, ctx): WireGuardEndpoint => {
  const address = [
    proxy.ip === undefined ? undefined : toPrefix(proxy.ip, '32'),
    proxy.ipv6 === undefined ? undefined : toPrefix(proxy.ipv6, '128'),
  ].filter(entry => entry !== undefined)

  if (address.length === 0) {
    ctx.addIssue({ code: 'custom', message: 'a WireGuard endpoint needs "ip" or "ipv6"' })
    return z.NEVER
  }

  const peers = buildPeers(proxy)
  if (peers.length === 0) {
    ctx.addIssue({ code: 'custom', message: 'a WireGuard endpoint needs "public-key" or a "peers" list' })
    return z.NEVER
  }

  return omitUndefined({
    type: 'wireguard' as const,
    tag: proxy.name,
    ...convertDialFields(proxy),
    address,
    private_key: proxy['private-key'],
    mtu: proxy.mtu,
    peers,
  })
}).pipe(SingboxEndpointWireGuard)
