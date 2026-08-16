import type { z } from 'zod'
import { omitUndefined } from '../object.ts'
import { ClashProxyHttp } from '../schemas/clash.ts'
import { SingboxOutboundHttp } from '../schemas/singbox.ts'
import { convertDialFields, convertTLSTransport } from './shared.ts'

export const HttpPipeline = ClashProxyHttp.transform((proxy): z.input<typeof SingboxOutboundHttp> =>
  omitUndefined({
    type: 'http' as const,
    tag: proxy.name,
    server: proxy.server,
    server_port: proxy.port,
    ...convertDialFields(proxy),
    username: proxy.username,
    // A password without a username is meaningless to sing-box.
    password: proxy.username === undefined ? undefined : proxy.password,
    tls: proxy.tls === true ? convertTLSTransport(proxy) : undefined,
  }),
).pipe(SingboxOutboundHttp)
