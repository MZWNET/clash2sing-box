import { z } from 'zod'
import { ClashProxySocks5, SingboxOutboundSocks } from '../types.ts'

const convertSocks5ToSocks = z.function({
  input: [ClashProxySocks5],
  output: SingboxOutboundSocks,
})
export const doConvertSocks5ToSocks = convertSocks5ToSocks.implement(proxy => {
  const outbound: z.infer<typeof SingboxOutboundSocks> = {
    type: 'socks',
    tag: proxy.name,
    server: proxy.server,
    server_port: proxy.port,
  }

  if (proxy.username !== undefined) {
    outbound.username = proxy.username
    if (proxy.password !== undefined) {
      outbound.password = proxy.password
    }
  }
  if (proxy.tls === true) {
    throw new Error('Unsupported layer tls')
  }

  return outbound
})
