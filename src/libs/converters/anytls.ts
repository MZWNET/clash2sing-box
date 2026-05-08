import { z } from 'zod'
import { ClashProxyAnyTls, SingboxOutboundAnyTls } from '../types.ts'
import { doConvertTLSTransport } from './shared.ts'

const convertAnyTls = z.function({
  input: [ClashProxyAnyTls],
  output: SingboxOutboundAnyTls,
})
export const doConvertAnyTls = convertAnyTls.implement((proxy) => {
  const outbound: z.infer<typeof SingboxOutboundAnyTls> = {
    type: 'anytls',
    tag: proxy.name,
    server: proxy.server,
    server_port: proxy.port,
    password: proxy.password,
    tls: doConvertTLSTransport(proxy),
  }

  if (proxy['idle-session-check-interval'] !== undefined) {
    outbound.idle_session_check_interval = `${
      proxy['idle-session-check-interval']
    }s`
  }
  if (proxy['idle-session-timeout'] !== undefined) {
    outbound.idle_session_timeout = `${proxy['idle-session-timeout']}s`
  }
  if (proxy['min-idle-session'] !== undefined) {
    outbound.min_idle_session = proxy['min-idle-session']
  }

  return outbound
})
