import { z } from 'zod'
import { omitUndefined } from '../object.ts'
import { ClashProxySnell } from '../schemas/clash.ts'
import { SingboxOutboundSnell } from '../schemas/singbox.ts'
import { convertDialFields, convertNetwork } from './shared.ts'

/**
 * mihomo speaks Snell v1-v5 while sing-box implements v4 and v6, so only version 4
 * actually overlaps. Anything else is reported rather than silently mis-converted.
 */
export const SnellPipeline = ClashProxySnell.transform((proxy, ctx): z.input<typeof SingboxOutboundSnell> => {
  if (proxy.version !== 4) {
    ctx.addIssue({
      code: 'custom',
      message: `sing-box implements Snell versions 4 and 6, but this proxy uses version ${(proxy.version ?? 1).toString()}`,
    })
    return z.NEVER
  }

  const obfs = proxy['obfs-opts']
  const mode = obfs?.mode
  // sing-box's Snell v4 obfuscation is `none` or `http`; mihomo also offers
  // tls/shadow-tls/restls/jls, which have no equivalent here.
  if (mode !== undefined && mode !== 'http' && mode !== 'none') {
    ctx.addIssue({
      code: 'custom',
      message: `sing-box does not support the Snell obfs mode "${mode}"`,
    })
    return z.NEVER
  }

  return omitUndefined({
    type: 'snell' as const,
    tag: proxy.name,
    server: proxy.server,
    server_port: proxy.port,
    ...convertDialFields(proxy),
    network: convertNetwork(proxy),
    version: 4 as const,
    psk: proxy.psk,
    reuse: proxy.reuse,
    obfs_mode: mode === 'http' ? ('http' as const) : undefined,
    obfs_host: mode === 'http' ? obfs?.host : undefined,
  })
}).pipe(SingboxOutboundSnell)
