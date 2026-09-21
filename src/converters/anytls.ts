import type { z } from 'zod'
import { ClashProxyAnyTls } from '../schemas/clash.ts'
import { SingboxOutboundAnyTls } from '../schemas/singbox.ts'
import { convertDialFields, convertTLSTransport } from './shared.ts'

/** Clash expresses these intervals as bare seconds; sing-box wants a duration string. */
function durationSeconds(seconds: number | undefined): string | undefined {
  return seconds === undefined ? undefined : `${seconds.toString()}s`
}

export const AnyTlsPipeline = ClashProxyAnyTls.transform((proxy): z.input<typeof SingboxOutboundAnyTls> => ({
  type: 'anytls' as const,
  tag: proxy.name,
  server: proxy.server,
  server_port: proxy.port,
  ...convertDialFields(proxy),
  // The one dial field AnyTLS refuses: it multiplexes over a session pool of its own, and
  // sing-box aborts with "tcp_fast_open is not supported with anytls outbound".
  tcp_fast_open: undefined,
  password: proxy.password,
  tls: convertTLSTransport(proxy),
  idle_session_check_interval: durationSeconds(proxy['idle-session-check-interval']),
  idle_session_timeout: durationSeconds(proxy['idle-session-timeout']),
  min_idle_session: proxy['min-idle-session'],
})).pipe(SingboxOutboundAnyTls)
