import { z } from 'zod'

/**
 * Dial options mihomo accepts on every proxy. They map onto sing-box's shared
 * "Dial Fields", which likewise apply to every outbound.
 */
const ClashDialFields = {
  udp: z.boolean().optional(),
  'ip-version': z.enum(['dual', 'ipv4', 'ipv6', 'ipv4-prefer', 'ipv6-prefer']).optional(),
  tfo: z.boolean().optional(),
  mptcp: z.boolean().optional(),
  'interface-name': z.string().optional(),
  'routing-mark': z.number().optional(),
  'dialer-proxy': z.string().optional(),
}

/** mihomo's multiplex block. `protocol` uses the same names as sing-box. */
export const ClashSmux = z.object({
  enabled: z.boolean().optional(),
  protocol: z.enum(['smux', 'yamux', 'h2mux']).optional(),
  'max-connections': z.number().optional(),
  'min-streams': z.number().optional(),
  'max-streams': z.number().optional(),
  padding: z.boolean().optional(),
  // `statistic` and `only-tcp` have no sing-box equivalent and are dropped.
  statistic: z.boolean().optional(),
  'only-tcp': z.boolean().optional(),
  'brutal-opts': z
    .object({
      enabled: z.boolean().optional(),
      up: z.number().optional(),
      down: z.number().optional(),
    })
    .optional(),
})

/** Fields shared by every Clash proxy, regardless of protocol. */
const ClashProxyBase = z.object({
  name: z.string(),
  server: z.string(),
  port: z.number(),
  ...ClashDialFields,
})

const ClashRealityOpts = z.object({
  'public-key': z.string(),
  'short-id': z.string().optional(),
  'spider-x': z.string().optional(),
})

const ClashEchOpts = z.object({
  enable: z.boolean(),
  config: z.string().optional(),
  'query-server-name': z.string().optional(),
})

/**
 * Fields shared by every proxy that can carry a TLS layer.
 *
 * `fingerprint`/`client-fingerprint`/`reality-opts`/`ech-opts` live here rather than on
 * individual protocols so that a single TLS converter can handle them for every protocol —
 * previously REALITY was only wired up for Hysteria2, which cannot even use it.
 */
export const ClashProxyBaseTLS = ClashProxyBase.extend({
  tls: z.boolean().optional().meta({
    description: 'Only exists on the following optionally tls-enabled proxies: http, socks, v2ray protocols',
  }),
  'skip-cert-verify': z.boolean().optional(),
  alpn: z.array(z.string()).optional(),
  servername: z.string().optional().meta({
    deprecated: true,
    description: 'Only used by v2ray protocols',
  }),
  sni: z.string().optional(),
  fingerprint: z.string().optional(),
  'client-fingerprint': z.string().optional(),
  'reality-opts': ClashRealityOpts.optional(),
  'ech-opts': ClashEchOpts.optional(),
  certificate: z.string().optional(),
  'x-clash2singbox-certificate': z.array(z.string()).optional(),
  'x-clash2singbox-certificate-public-key-sha256': z.string().optional(),
})

/**
 * The V2Ray transport blocks. Shared by Vmess/VLESS *and* Trojan — sing-box's Trojan
 * outbound accepts a `transport` too, which this converter used to drop entirely.
 */
export const ClashProxyBaseTransport = ClashProxyBaseTLS.extend({
  network: z.enum(['ws', 'h2', 'http', 'grpc', 'tcp']).optional(),
  smux: ClashSmux.optional(),
  'ws-opts': z
    .object({
      path: z.string().optional(),
      headers: z.record(z.string(), z.string()).optional(),
      'max-early-data': z.number().optional(),
      'early-data-header-name': z.string().optional(),
      'v2ray-http-upgrade': z.boolean().optional(),
      'v2ray-http-upgrade-fast-open': z.boolean().optional(),
    })
    .optional(),
  'h2-opts': z
    .object({
      host: z.array(z.string()).optional(),
      path: z.string().optional(),
    })
    .optional(),
  'http-opts': z
    .object({
      method: z.string().optional(),
      path: z.array(z.string()).optional(),
      headers: z.record(z.string(), z.array(z.string())).optional(),
    })
    .optional(),
  'grpc-opts': z
    .object({
      'grpc-service-name': z.string().optional(),
    })
    .optional(),
})

export const ClashProxyBaseVmessOrVLESS = ClashProxyBaseTransport.extend({
  uuid: z.string(),
  'packet-encoding': z.enum(['packetaddr', 'xudp']).optional(),
})

export const ClashProxyAnyTls = ClashProxyBaseTLS.extend({
  type: z.literal('anytls'),
  password: z.string(),
  'idle-session-check-interval': z.number().optional(),
  'idle-session-timeout': z.number().optional(),
  'min-idle-session': z.number().optional(),
})

export const ClashProxyDirect = z.object({
  type: z.literal('direct'),
  name: z.string(),
  // mihomo's direct proxy has no server/port.
  ...ClashDialFields,
})

export const ClashProxyHttp = ClashProxyBaseTLS.extend({
  type: z.literal('http'),
  username: z.string().optional(),
  password: z.string().optional(),
})

export const ClashProxyHysteria = ClashProxyBaseTLS.extend({
  type: z.literal('hysteria'),
  'auth-str': z.string().optional(),
  obfs: z.string().optional(),
  protocol: z.enum(['udp', 'wechat-video', 'faketcp']),
  up: z.string(),
  down: z.string(),
})

export const ClashProxyHysteria2 = ClashProxyBaseTLS.extend({
  type: z.literal('hysteria2'),
  password: z.string(),
  up: z.string().optional(),
  down: z.string().optional(),
  obfs: z.string().optional(),
  'obfs-password': z.string().optional(),
  ports: z.string().optional(),
})

export const ClashProxySocks5 = ClashProxyBaseTLS.extend({
  type: z.literal('socks5'),
  username: z.string().optional(),
  password: z.string().optional(),
})

/**
 * Snell. sing-box implements versions 4 and 6 only, while mihomo speaks 1-5, so just
 * version 4 overlaps; the converter reports the rest as unsupported.
 */
export const ClashProxySnell = ClashProxyBase.extend({
  type: z.literal('snell'),
  psk: z.string(),
  version: z.coerce.number().optional(),
  reuse: z.boolean().optional(),
  'obfs-opts': z
    .object({
      mode: z.string().optional(),
      host: z.string().optional(),
      password: z.string().optional(),
      version: z.coerce.number().optional(),
    })
    .optional(),
})

export const ClashProxySSH = ClashProxyBase.extend({
  type: z.literal('ssh'),
  username: z.string(),
  password: z.string().optional(),
  'private-key': z.string().optional(),
  'private-key-passphrase': z.string().optional(),
  'host-key': z.array(z.string()).optional(),
  'host-key-algorithms': z.array(z.string()).optional(),
})

export const ClashProxyShadowsocks = ClashProxyBase.extend({
  type: z.literal('ss'),
  cipher: z.enum([
    // Temporary workaround
    '2022-blake3-aes-128-gcm',
    '2022-blake3-aes-256-gcm',
    '2022-blake3-chacha20-poly1305',
    'aes-128-gcm',
    'aes-192-gcm',
    'aes-256-gcm',
    'aes-128-cfb',
    'aes-192-cfb',
    'aes-256-cfb',
    'aes-128-ctr',
    'aes-192-ctr',
    'aes-256-ctr',
    'rc4-md5',
    'chacha20-ietf',
    'xchacha20',
    'chacha20-ietf-poly1305',
    'xchacha20-ietf-poly1305',
  ]),
  password: z.string(),
  smux: ClashSmux.optional(),
  'client-fingerprint': z.string().optional(),
  plugin: z.enum(['obfs', 'v2ray-plugin', 'shadow-tls']).optional(),
  'plugin-opts': z
    .object({
      mode: z.enum(['http', 'tls', 'websocket']).optional(),
      tls: z.boolean().optional(),
      host: z.string().optional(),
      path: z.string().optional(),
      mux: z.boolean().optional(),
      // shadow-tls only
      password: z.string().optional(),
      version: z.coerce.number().optional(),
    })
    .optional(),
  'udp-over-tcp': z.boolean().optional(),
  'udp-over-tcp-version': z.union([z.literal(1), z.literal(2)]).optional(),
})

export const ClashProxyTrojan = ClashProxyBaseTransport.extend({
  type: z.literal('trojan'),
  password: z.string(),
})

export const ClashProxyTUIC = ClashProxyBaseTLS.extend({
  type: z.literal('tuic'),
  uuid: z.string(),
  password: z.string().optional(),
  'heartbeat-interval': z.number().optional(),
  'reduce-rtt': z.boolean().optional(),
  'udp-relay-mode': z.enum(['native', 'quic']).optional(),
  'congestion-controller': z.enum(['cubic', 'new_reno', 'bbr']).optional(),
  'udp-over-stream': z.boolean().optional(),
})

export const ClashProxyVmess = ClashProxyBaseVmessOrVLESS.extend({
  type: z.literal('vmess'),
  // Temporary workaround
  alterId: z.coerce.number(),
  cipher: z.enum(['aes-128-gcm', 'chacha20-poly1305', 'auto', 'none', 'zero']),
  'global-padding': z.boolean().optional(),
  'authenticated-length': z.boolean().optional(),
})

export const ClashProxyVLESS = ClashProxyBaseVmessOrVLESS.extend({
  type: z.literal('vless'),
  flow: z.string().optional(),
  security: z.enum(['tls', 'reality', 'none']).optional(),
  encryption: z.string().optional(),
  'client-version': z.string().optional(),
}).loose()

const ClashWireGuardPeer = z.object({
  server: z.string().optional(),
  port: z.number().optional(),
  'public-key': z.string(),
  'pre-shared-key': z.string().optional(),
  'allowed-ips': z.array(z.string()).optional(),
  reserved: z.union([z.array(z.number()), z.string()]).optional(),
})

/**
 * WireGuard. sing-box removed the WireGuard *outbound* in 1.13.0, so this converts to a
 * top-level `endpoints` entry instead.
 */
export const ClashProxyWireGuard = z.object({
  type: z.literal('wireguard'),
  name: z.string(),
  server: z.string().optional(),
  port: z.number().optional(),
  'private-key': z.string(),
  'public-key': z.string().optional(),
  'pre-shared-key': z.string().optional(),
  ip: z.string().optional(),
  ipv6: z.string().optional(),
  mtu: z.number().optional(),
  reserved: z.union([z.array(z.number()), z.string()]).optional(),
  'allowed-ips': z.array(z.string()).optional(),
  'persistent-keepalive': z.number().optional(),
  peers: z.array(ClashWireGuardPeer).optional(),
  ...ClashDialFields,
})

/** Rejects connections. Maps onto sing-box's `block` outbound, which takes no fields. */
export const ClashProxyReject = z.object({
  type: z.literal('reject'),
  name: z.string(),
  ...ClashDialFields,
})

/**
 * Tailscale. Like WireGuard this is an `endpoints` entry, not an outbound, and it has no
 * server address of its own — it dials the coordination server.
 */
export const ClashProxyTailscale = z.object({
  type: z.literal('tailscale'),
  name: z.string(),
  'auth-key': z.string().optional(),
  'control-url': z.string().optional(),
  'state-dir': z.string().optional(),
  ephemeral: z.boolean().optional(),
  hostname: z.string().optional(),
  'accept-routes': z.boolean().optional(),
  'exit-node': z.string().optional(),
  'exit-node-allow-lan-access': z.boolean().optional(),
  ...ClashDialFields,
})

/**
 * OpenVPN. mihomo always speaks TLS mode, and its `ca`/`cert`/`key`/`tls-*` fields carry
 * inline PEM copied out of an `.ovpn` file rather than paths.
 */
export const ClashProxyOpenVPN = z.object({
  type: z.literal('openvpn'),
  name: z.string(),
  server: z.string(),
  port: z.number().optional(),
  proto: z.enum(['udp', 'tcp']).optional(),
  username: z.string().optional(),
  password: z.string().optional(),
  ca: z.string().optional(),
  cert: z.string().optional(),
  key: z.string().optional(),
  'tls-auth': z.string().optional(),
  'tls-crypt': z.string().optional(),
  'tls-crypt-v2': z.string().optional(),
  'key-direction': z.string().optional(),
  cipher: z.string().optional(),
  'data-ciphers': z.array(z.string()).optional(),
  'data-ciphers-fallback': z.string().optional(),
  auth: z.string().optional(),
  'comp-lzo': z.string().optional(),
  dev: z.string().optional(),
  mtu: z.number().optional(),
  ping: z.number().optional(),
  'ping-restart': z.number().optional(),
  'handshake-timeout': z.number().optional(),
  ...ClashDialFields,
})

/**
 * Lenient shape used to identify a proxy before protocol-specific parsing.
 *
 * Only `name` and `type` are required: `direct` and `wireguard` legitimately omit
 * `server`/`port`, and a protocol that does need them reports a precise error itself.
 * The cross-cutting fields use `.catch(undefined)` so a malformed value here never
 * prevents identification.
 */
export const ClashProxyRaw = z.looseObject({
  name: z.string(),
  type: z.string(),
  server: z.string().optional().catch(undefined),
  port: z.number().optional().catch(undefined),
  udp: z.boolean().optional().catch(undefined),
  'ip-version': z.enum(['dual', 'ipv4', 'ipv6', 'ipv4-prefer', 'ipv6-prefer']).optional().catch(undefined),
  flow: z.string().optional().catch(undefined),
})

/**
 * Proxies are held as `unknown` and validated one at a time. Typing the array element
 * here instead would mean a single malformed proxy fails the whole array, silently
 * dropping every other proxy in the subscription.
 */
export const Clash = z.looseObject({
  proxies: z.array(z.unknown()).optional(),
})

/** A document is a Clash config when it carries a `proxies` list. */
export const ClashConfigProbe = z.looseObject({
  proxies: z.array(z.unknown()),
})

export type ClashDialInput = z.infer<typeof ClashProxyBase>
export type ClashProxyBaseTLSInput = z.infer<typeof ClashProxyBaseTLS>
export type ClashProxyBaseTransportInput = z.infer<typeof ClashProxyBaseTransport>
export type ClashProxyBaseVmessOrVLESSInput = z.infer<typeof ClashProxyBaseVmessOrVLESS>
export type ClashProxyRawInput = z.infer<typeof ClashProxyRaw>
export type ClashSmuxInput = z.infer<typeof ClashSmux>
