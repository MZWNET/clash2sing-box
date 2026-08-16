import { z } from 'zod'
import { omitUndefined } from '../object.ts'
import { ClashProxyHysteria2 } from '../schemas/clash.ts'
import { SingboxOutboundHysteria2 } from '../schemas/singbox.ts'
import { convertDialFields, convertNetwork, convertTLSTransport } from './shared.ts'

/**
 * Clash writes speeds as free-form strings such as `"100 Mbps"`; sing-box wants a number.
 * `Number.parseInt` already stops at the first non-digit, so no pattern matching is needed.
 * Anything unparseable (`""`, `"abc"`) falls back to "unset".
 */
const Mbps = z
  .string()
  .transform(speed => Number.parseInt(speed, 10))
  .pipe(z.number().int().nonnegative())
  .optional()
  .catch(undefined)

/** `"443,8443"`, `"443/8443"` and `"1000-2000"` all describe port sets/ranges. */
const ServerPorts = z
  .string()
  .transform(ports => {
    const parsed = ports
      .replaceAll('/', ',')
      .split(',')
      .filter(Boolean)
      .map(part => part.replaceAll('-', ':'))
    return parsed.length === 0 ? undefined : parsed
  })
  .optional()
  .catch(undefined)

export const Hysteria2Pipeline = ClashProxyHysteria2.transform((proxy): z.input<typeof SingboxOutboundHysteria2> =>
  omitUndefined({
    type: 'hysteria2' as const,
    tag: proxy.name,
    server: proxy.server,
    server_port: proxy.port,
    ...convertDialFields(proxy),
    network: convertNetwork(proxy),
    server_ports: ServerPorts.parse(proxy.ports),
    up_mbps: Mbps.parse(proxy.up),
    down_mbps: Mbps.parse(proxy.down),
    password: proxy.password,
    obfs:
      proxy.obfs === undefined || proxy['obfs-password'] === undefined
        ? undefined
        : { type: proxy.obfs, password: proxy['obfs-password'] },
    tls: convertTLSTransport(proxy),
  }),
).pipe(SingboxOutboundHysteria2)
