import type { ClashProxyBaseTLSInput, ClashProxyBaseTransportInput, ClashSmuxInput } from '../schemas/clash.ts'
import type {
  SingboxMultiplexInput,
  SingboxOutboundCommonTls,
  SingboxOutboundCommonTransport,
} from '../schemas/singbox.ts'
import { Buffer } from 'node:buffer'

/**
 * The dial options mihomo puts on every proxy. Declared structurally so that `direct`
 * and `wireguard`, which have no `server`/`port`, can use this too.
 */
export interface ClashDialOptions {
  udp?: boolean | undefined
  tfo?: boolean | undefined
  mptcp?: boolean | undefined
  'interface-name'?: string | undefined
  'routing-mark'?: number | undefined
  'dialer-proxy'?: string | undefined
}

export interface SingboxDialOptions {
  detour?: string | undefined
  bind_interface?: string | undefined
  routing_mark?: number | undefined
  tcp_fast_open?: boolean | undefined
  tcp_multi_path?: boolean | undefined
}

/**
 * Map mihomo's per-proxy dial options onto sing-box's shared Dial Fields.
 *
 * These apply to every outbound on both sides, so every converter spreads this in —
 * previously they were only honoured by SSH and Hysteria2, and VLESS parsed then dropped them.
 */
export function convertDialFields(proxy: ClashDialOptions): SingboxDialOptions {
  return {
    detour: proxy['dialer-proxy'],
    bind_interface: proxy['interface-name'],
    routing_mark: proxy['routing-mark'],
    tcp_fast_open: proxy.tfo,
    tcp_multi_path: proxy.mptcp,
  }
}

/**
 * sing-box enables both networks by default; Clash's `udp: false` narrows it to TCP.
 *
 * Kept separate from the dial fields because `network` is a per-outbound field that only
 * some outbounds accept. sing-box rejects configs containing unknown keys, so emitting
 * it on `direct`, `http`, `ssh`, `anytls` or `shadowtls` would break the entire config.
 */
export function convertNetwork(proxy: Pick<ClashDialOptions, 'udp'>): 'tcp' | undefined {
  return proxy.udp === false ? 'tcp' : undefined
}

/**
 * Map mihomo's `smux` onto sing-box's `multiplex`. The protocol names are identical on
 * both sides; `statistic` and `only-tcp` have no sing-box equivalent and are dropped.
 */
export function convertMultiplex(smux: ClashSmuxInput | undefined): SingboxMultiplexInput | undefined {
  if (smux?.enabled !== true) {
    return undefined
  }

  const brutal = smux['brutal-opts']
  return {
    enabled: true,
    protocol: smux.protocol,
    max_connections: smux['max-connections'],
    min_streams: smux['min-streams'],
    max_streams: smux['max-streams'],
    padding: smux.padding,
    // Both sides count bandwidth in Mbps, so the numbers carry over unchanged.
    brutal: brutal?.enabled === true ? { enabled: true, up_mbps: brutal.up, down_mbps: brutal.down } : undefined,
  }
}

/** sing-box takes PEM as a list of lines and joins them back with newlines. */
function splitPem(pem: string | undefined): string[] | undefined {
  const lines = pem?.split('\n').filter(line => line.trim() !== '')
  return lines === undefined || lines.length === 0 ? undefined : lines
}

/** A SHA-256 digest as mihomo writes it: hex, upper or lower case, colons optional. */
const CERTIFICATE_FINGERPRINT = /^(?:[\da-f]{2}:?){32}$/i

/**
 * Both sides pin on the SHA-256 of the whole certificate, so only the encoding differs:
 * mihomo writes hex, sing-box reads base64.
 *
 * Anything that is not that digest — a browser name left over from the days when
 * `fingerprint` meant uTLS, a truncated hash — is no pin at all, and mihomo rejects it too.
 * `convert` reports the drop.
 */
export function certificateSha256(fingerprint: string | undefined): string[] | undefined {
  if (fingerprint === undefined || !CERTIFICATE_FINGERPRINT.test(fingerprint.trim())) {
    return undefined
  }
  return [Buffer.from(fingerprint.trim().replaceAll(':', ''), 'hex').toString('base64')]
}

/**
 * mihomo carries the ECH config list as bare base64, sing-box as PEM.
 *
 * Handing the base64 over unwrapped is accepted by the JSON decoder and then fails at
 * startup with "invalid ECH configs pem".
 */
function echConfig(config: string | undefined): string[] | undefined {
  const base64 = config?.trim()
  return base64 === undefined || base64 === ''
    ? undefined
    : ['-----BEGIN ECH CONFIGS-----', base64, '-----END ECH CONFIGS-----']
}

/**
 * Build the sing-box TLS transport from a Clash proxy.
 *
 * REALITY, ECH and uTLS are handled here rather than per-protocol: previously they were
 * only wired up in the Hysteria2 converter — which cannot use REALITY at all, since it is
 * QUIC-based — while VLESS, the protocol that actually needs them, silently dropped them.
 *
 * `certificate`/`private-key` are the client half of a mutual-TLS pair, not a CA to trust —
 * the name is misleading on the mihomo side.
 */
export function convertTLSTransport(proxy: ClashProxyBaseTLSInput): SingboxOutboundCommonTls {
  const realityOpts = proxy['reality-opts']
  const echOpts = proxy['ech-opts']
  const clientCertificate = splitPem(proxy.certificate)
  const clientKey = splitPem(proxy['private-key'])
  // sing-box refuses a lone half: "client certificate and client key must be provided together".
  const mutualTLS = clientCertificate !== undefined && clientKey !== undefined

  return {
    enabled: true,
    // `sni` wins over the deprecated `servername`.
    server_name: proxy.sni ?? proxy.servername,
    insecure: proxy['skip-cert-verify'] === true ? true : undefined,
    alpn: proxy.alpn,
    certificate_sha256: certificateSha256(proxy.fingerprint),
    client_certificate: mutualTLS ? clientCertificate : undefined,
    client_key: mutualTLS ? clientKey : undefined,
    reality:
      realityOpts === undefined
        ? undefined
        : { enabled: true, public_key: realityOpts['public-key'], short_id: realityOpts['short-id'] },
    ech: echOpts?.enable === true ? { enabled: true, config: echConfig(echOpts.config) } : undefined,
    utls:
      proxy['client-fingerprint'] === undefined
        ? undefined
        : { enabled: true, fingerprint: proxy['client-fingerprint'] },
  }
}

/**
 * Map the Clash `*-opts` transport blocks onto a sing-box transport, if any apply.
 * Used by Vmess, VLESS and Trojan — sing-box's Trojan outbound takes a `transport` too.
 */
export function convertTransport(proxy: ClashProxyBaseTransportInput): SingboxOutboundCommonTransport | undefined {
  const httpOpts = proxy['http-opts']
  if (httpOpts !== undefined) {
    return {
      type: 'http',
      // sing-box takes a single path where Clash takes a list.
      path: httpOpts.path?.[0],
      method: httpOpts.method,
      headers:
        httpOpts.headers === undefined
          ? undefined
          : Object.fromEntries(
              Object.entries(httpOpts.headers)
                .filter(([, value]) => value[0] !== undefined)
                .map(([key, value]) => [key, value[0] as string]),
            ),
    }
  }

  const h2Opts = proxy['h2-opts']
  if (h2Opts !== undefined) {
    return { type: 'http', host: h2Opts.host, path: h2Opts.path }
  }

  const wsOpts = proxy['ws-opts']
  if (wsOpts !== undefined) {
    return wsOpts['v2ray-http-upgrade'] === true
      ? { type: 'httpupgrade', path: wsOpts.path, headers: wsOpts.headers }
      : {
          type: 'ws',
          path: wsOpts.path,
          headers: wsOpts.headers,
          max_early_data: wsOpts['max-early-data'],
          early_data_header_name: wsOpts['early-data-header-name'],
        }
  }

  const grpcOpts = proxy['grpc-opts']
  if (grpcOpts !== undefined) {
    return { type: 'grpc', service_name: grpcOpts['grpc-service-name'] }
  }

  return undefined
}
