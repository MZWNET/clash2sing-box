import { z } from 'zod'
import { ClashProxyTrojan, SingboxOutboundTrojan } from '../types.ts'
import { doConvertTLSTransport } from './shared.ts'

const convertTrojan = z.function({
  input: [ClashProxyTrojan],
  output: SingboxOutboundTrojan,
})
export const doConvertTrojan = convertTrojan.implement(proxy => {
  const outbound: z.infer<typeof SingboxOutboundTrojan> = {
    type: 'trojan',
    tag: proxy.name,
    server: proxy.server,
    server_port: proxy.port,
    password: proxy.password,
    tls: doConvertTLSTransport(proxy),
  }

  return outbound
})
