import type { z } from 'zod'
import { ClashProxyTUIC } from '../schemas/clash.ts'
import { SingboxOutboundTUIC } from '../schemas/singbox.ts'
import { convertDialFields, convertNetwork, convertTLSTransport } from './shared.ts'

export const TUICPipeline = ClashProxyTUIC.transform((proxy): z.input<typeof SingboxOutboundTUIC> => {
  // sing-box refuses both at once — "udp_over_stream is conflict with udp_relay_mode" —
  // whereas mihomo accepts both and lets UDP-over-stream win. `convert` reports the drop.
  const udpOverStream = proxy['udp-over-stream'] === true

  return {
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
    udp_relay_mode: udpOverStream ? undefined : proxy['udp-relay-mode'],
    congestion_control: proxy['congestion-controller'],
    udp_over_stream: udpOverStream ? true : undefined,
    tls: convertTLSTransport(proxy),
  }
}).pipe(SingboxOutboundTUIC)
