import type { z } from 'zod'
import { omitUndefined } from '../object.ts'
import { ClashProxyAnyTls } from '../schemas/clash.ts'
import { SingboxOutboundAnyTls } from '../schemas/singbox.ts'
import { convertDialFields, convertTLSTransport } from './shared.ts'

/** Clash expresses these intervals as bare seconds; sing-box wants a duration string. */
function durationSeconds(seconds: number | undefined): string | undefined {
  return seconds === undefined ? undefined : `${seconds.toString()}s`
}

export const AnyTlsPipeline = ClashProxyAnyTls.transform((proxy): z.input<typeof SingboxOutboundAnyTls> =>
  omitUndefined({
    type: 'anytls' as const,
    tag: proxy.name,
    server: proxy.server,
    server_port: proxy.port,
    ...convertDialFields(proxy),
    password: proxy.password,
    tls: convertTLSTransport(proxy),
    idle_session_check_interval: durationSeconds(proxy['idle-session-check-interval']),
    idle_session_timeout: durationSeconds(proxy['idle-session-timeout']),
    min_idle_session: proxy['min-idle-session'],
  }),
).pipe(SingboxOutboundAnyTls)
