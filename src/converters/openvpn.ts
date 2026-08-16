import { z } from 'zod'
import { omitUndefined } from '../object.ts'
import { ClashProxyOpenVPN } from '../schemas/clash.ts'
import { SingboxEndpointOpenVPNClient } from '../schemas/singbox.ts'
import { convertDialFields } from './shared.ts'

type OpenVPNProxy = z.infer<typeof ClashProxyOpenVPN>
type OpenVPNEndpoint = z.input<typeof SingboxEndpointOpenVPNClient>
type ControlWrap = NonNullable<OpenVPNEndpoint['tls']['control_wrap']>

/** mihomo's default, matching the OpenVPN default. */
const DEFAULT_PORT = 1194

/** Clash counts these in seconds; sing-box takes duration strings. */
function seconds(value: number | undefined): string | undefined {
  return value === undefined || value === 0 ? undefined : `${value.toString()}s`
}

/**
 * `tls-auth`, `tls-crypt` and `tls-crypt-v2` are mutually exclusive ways of wrapping the
 * OpenVPN control channel; sing-box expresses all three through one tagged object.
 */
function buildControlWrap(proxy: OpenVPNProxy): ControlWrap | undefined {
  // mihomo's `key-direction` default is "bidirectional", which sing-box cannot express;
  // it accepts only "server"/"client", so anything else is left unset.
  const direction = proxy['key-direction']
  const keyDirection = direction === 'server' || direction === 'client' ? direction : undefined

  if (proxy['tls-crypt-v2'] !== undefined) {
    return { type: 'tls_crypt_v2', key: [proxy['tls-crypt-v2']] }
  }
  if (proxy['tls-crypt'] !== undefined) {
    return { type: 'tls_crypt', key: [proxy['tls-crypt']] }
  }
  if (proxy['tls-auth'] !== undefined) {
    return { type: 'tls_auth', key: [proxy['tls-auth']], direction: keyDirection }
  }
  return undefined
}

export const OpenVPNPipeline = ClashProxyOpenVPN.transform((proxy, ctx): OpenVPNEndpoint => {
  // sing-box implements TUN only; there is no TAP support to map `dev: tap` onto.
  if (proxy.dev !== undefined && proxy.dev !== 'tun') {
    ctx.addIssue({ code: 'custom', message: `sing-box does not support the OpenVPN device "${proxy.dev}"` })
    return z.NEVER
  }

  return omitUndefined({
    type: 'openvpn-client' as const,
    tag: proxy.name,
    server: proxy.server,
    server_port: proxy.port ?? DEFAULT_PORT,
    ...convertDialFields(proxy),
    // On OpenVPN `network` is the transport protocol, so it comes from `proto` — not from
    // `udp`, which on other protocols narrows the outbound to TCP.
    network: proxy.proto,
    username: proxy.username,
    password: proxy.password,
    tls: omitUndefined({
      // mihomo carries inline PEM copied out of the .ovpn file, never a path.
      certificate: proxy.ca === undefined ? undefined : [proxy.ca],
      client_certificate: proxy.cert === undefined ? undefined : [proxy.cert],
      client_key: proxy.key === undefined ? undefined : [proxy.key],
      control_wrap: buildControlWrap(proxy),
    }),
    data_ciphers: proxy['data-ciphers'],
    // mihomo's `cipher` is the legacy single data-channel cipher, which modern OpenVPN
    // treats as the fallback. An explicit `data-ciphers-fallback` wins over it.
    data_ciphers_fallback: proxy['data-ciphers-fallback'] ?? proxy.cipher,
    auth: proxy.auth,
    compression_lzo: proxy['comp-lzo'],
    mtu: proxy.mtu,
    ping_interval: seconds(proxy.ping),
    ping_restart: seconds(proxy['ping-restart']),
    handshake_window: seconds(proxy['handshake-timeout']),
  })
}).pipe(SingboxEndpointOpenVPNClient)
