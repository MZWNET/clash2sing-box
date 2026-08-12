import { z } from 'zod'
import { ClashProxyTUIC, SingboxOutboundTUIC } from '../types.ts'
import { doConvertTLSTransport } from './shared.ts'

const convertTUIC = z.function({
  input: [ClashProxyTUIC],
  output: SingboxOutboundTUIC,
})
export const doConvertTUIC = convertTUIC.implement(proxy => {
  const outbound: z.infer<typeof SingboxOutboundTUIC> = {
    type: 'tuic',
    tag: proxy.name,
    server: proxy.server,
    server_port: proxy.port,
    uuid: proxy.uuid,
    tls: doConvertTLSTransport(proxy),
  }

  if (proxy.password !== undefined) {
    outbound.password = proxy.password
  }
  if (proxy['heartbeat-interval'] !== undefined) {
    outbound.heartbeat = `${(proxy['heartbeat-interval'] / 1000).toString()}s`
  }
  if (proxy['reduce-rtt'] === true) {
    outbound.zero_rtt_handshake = true
  }
  if (proxy['udp-relay-mode'] !== undefined) {
    outbound.udp_relay_mode = proxy['udp-relay-mode']
  }
  if (proxy['congestion-controller'] !== undefined) {
    outbound.congestion_control = proxy['congestion-controller']
  }
  if (proxy['udp-over-stream'] === true) {
    outbound.udp_over_stream = true
  }

  return outbound
})
