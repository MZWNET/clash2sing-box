import type { z } from 'zod'
import { omitUndefined } from '../object.ts'
import { ClashProxyTUIC } from '../schemas/clash.ts'
import { SingboxOutboundTUIC } from '../schemas/singbox.ts'
import { convertDialFields, convertNetwork, convertTLSTransport } from './shared.ts'

export const TUICPipeline = ClashProxyTUIC.transform((proxy): z.input<typeof SingboxOutboundTUIC> =>
  omitUndefined({
    type: 'tuic' as const,
    tag: proxy.name,
    server: proxy.server,
    server_port: proxy.port,
    ...convertDialFields(proxy),
    network: convertNetwork(proxy),
    uuid: proxy.uuid,
    password: proxy.password,
    // Clash counts milliseconds; sing-box wants a duration string.
    heartbeat:
      proxy['heartbeat-interval'] === undefined ? undefined : `${(proxy['heartbeat-interval'] / 1000).toString()}s`,
    zero_rtt_handshake: proxy['reduce-rtt'] === true ? true : undefined,
    udp_relay_mode: proxy['udp-relay-mode'],
    congestion_control: proxy['congestion-controller'],
    udp_over_stream: proxy['udp-over-stream'] === true ? true : undefined,
    tls: convertTLSTransport(proxy),
  }),
).pipe(SingboxOutboundTUIC)
