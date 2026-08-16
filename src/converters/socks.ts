import { z } from 'zod'
import { omitUndefined } from '../object.ts'
import { ClashProxySocks5 } from '../schemas/clash.ts'
import { SingboxOutboundSocks } from '../schemas/singbox.ts'
import { convertDialFields, convertNetwork } from './shared.ts'

export const Socks5Pipeline = ClashProxySocks5.transform((proxy, ctx): z.input<typeof SingboxOutboundSocks> => {
  if (proxy.tls === true) {
    // Reported as a parse issue rather than thrown, so the orchestrator skips just this
    // proxy instead of aborting the whole conversion.
    ctx.addIssue({ code: 'custom', message: 'sing-box does not support a TLS layer on SOCKS' })
    return z.NEVER
  }

  return omitUndefined({
    type: 'socks' as const,
    tag: proxy.name,
    server: proxy.server,
    server_port: proxy.port,
    ...convertDialFields(proxy),
    network: convertNetwork(proxy),
    username: proxy.username,
    // A password without a username is meaningless to sing-box.
    password: proxy.username === undefined ? undefined : proxy.password,
  })
}).pipe(SingboxOutboundSocks)
