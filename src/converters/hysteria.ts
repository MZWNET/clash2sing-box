import { z } from 'zod'
import { omitUndefined } from '../object.ts'
import { ClashProxyHysteria } from '../schemas/clash.ts'
import { SingboxOutboundHysteria } from '../schemas/singbox.ts'
import { convertDialFields, convertNetwork, convertTLSTransport } from './shared.ts'

export const HysteriaPipeline = ClashProxyHysteria.transform((proxy, ctx): z.input<typeof SingboxOutboundHysteria> => {
  if (proxy.protocol !== 'udp') {
    // Reported as a parse issue rather than thrown, so the orchestrator skips just this
    // proxy instead of aborting the whole conversion.
    ctx.addIssue({
      code: 'custom',
      message: `sing-box does not support the Hysteria protocol "${proxy.protocol}"`,
    })
    return z.NEVER
  }

  return omitUndefined({
    type: 'hysteria' as const,
    tag: proxy.name,
    server: proxy.server,
    server_port: proxy.port,
    ...convertDialFields(proxy),
    network: convertNetwork(proxy),
    up: proxy.up,
    down: proxy.down,
    obfs: proxy.obfs,
    auth_str: proxy['auth-str'],
    tls: convertTLSTransport(proxy),
  })
}).pipe(SingboxOutboundHysteria)
