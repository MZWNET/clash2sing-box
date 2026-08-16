import type { z } from 'zod'
import { omitUndefined } from '../object.ts'
import { ClashProxyTrojan } from '../schemas/clash.ts'
import { SingboxOutboundTrojan } from '../schemas/singbox.ts'
import { convertDialFields, convertMultiplex, convertNetwork, convertTLSTransport, convertTransport } from './shared.ts'

export const TrojanPipeline = ClashProxyTrojan.transform((proxy): z.input<typeof SingboxOutboundTrojan> =>
  omitUndefined({
    type: 'trojan' as const,
    tag: proxy.name,
    server: proxy.server,
    server_port: proxy.port,
    ...convertDialFields(proxy),
    network: convertNetwork(proxy),
    password: proxy.password,
    // sing-box's Trojan outbound accepts a transport; this used to be dropped, which
    // silently produced an unusable config for Trojan over WebSocket/gRPC.
    transport: convertTransport(proxy),
    multiplex: convertMultiplex(proxy.smux),
    tls: convertTLSTransport(proxy),
  }),
).pipe(SingboxOutboundTrojan)
