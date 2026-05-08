import { z } from 'zod'
import { ClashProxyVLESS, SingboxOutboundVLESS } from '../types.ts'
import {
  doConvertTLSTransport,
  doConvertVmessOrVLESSTransport,
} from './shared.ts'

const convertVLESS = z.function({
  input: [ClashProxyVLESS],
  output: SingboxOutboundVLESS,
})
export const doConvertVLESS = convertVLESS.implement((proxy) => {
  const outbound: z.infer<typeof SingboxOutboundVLESS> = {
    type: 'vless',
    tag: proxy.name,
    server: proxy.server,
    server_port: proxy.port,
    uuid: proxy.uuid,
  }

  const transport = doConvertVmessOrVLESSTransport(proxy)
  if (transport) {
    outbound.transport = transport
  }

  if (proxy.flow !== undefined) {
    outbound.flow = proxy.flow
  }
  if (proxy.tls !== undefined) {
    outbound.tls = doConvertTLSTransport(proxy)
  }

  return outbound
})
