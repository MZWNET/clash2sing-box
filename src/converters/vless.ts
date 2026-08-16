import type { z } from 'zod'
import { omitUndefined } from '../object.ts'
import { ClashProxyVLESS } from '../schemas/clash.ts'
import { SingboxOutboundVLESS } from '../schemas/singbox.ts'
import { convertDialFields, convertMultiplex, convertNetwork, convertTLSTransport, convertTransport } from './shared.ts'

/** The only flow sing-box implements. */
export const VLESS_FLOW = 'xtls-rprx-vision'

function usesTLS(proxy: {
  tls?: boolean | undefined
  security?: string | undefined
  'reality-opts'?: unknown
  'ech-opts'?: unknown
}): boolean {
  return (
    proxy.tls === true ||
    proxy.security === 'tls' ||
    proxy.security === 'reality' ||
    proxy['reality-opts'] !== undefined ||
    proxy['ech-opts'] !== undefined
  )
}

export const VLESSPipeline = ClashProxyVLESS.transform((proxy): z.input<typeof SingboxOutboundVLESS> =>
  omitUndefined({
    type: 'vless' as const,
    tag: proxy.name,
    server: proxy.server,
    server_port: proxy.port,
    ...convertDialFields(proxy),
    network: convertNetwork(proxy),
    uuid: proxy.uuid,
    // sing-box implements exactly one flow, so anything non-empty normalizes onto it.
    // `convert()` reports the substitution as a warning.
    flow: proxy.flow === undefined ? undefined : VLESS_FLOW,
    packet_encoding: proxy['packet-encoding'],
    transport: convertTransport(proxy),
    multiplex: convertMultiplex(proxy.smux),
    // REALITY implies TLS even when `tls: true` is absent, which is how many
    // VLESS+REALITY subscriptions are written.
    tls: usesTLS(proxy) ? convertTLSTransport(proxy) : undefined,
  }),
).pipe(SingboxOutboundVLESS)
