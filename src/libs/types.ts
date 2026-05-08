import { z } from 'zod'

const ClashProxy = z.object({
  'name': z.string(),
  'server': z.string(),
  'port': z.number(),
  'udp': z.optional(z.boolean()),
  'ip-version': z.optional(
    z.enum(['dual', 'ipv4', 'ipv6', 'ipv4-prefer', 'ipv6-prefer']),
  ),
})
export const ClashProxyBaseTLS = ClashProxy.extend({
  'tls': z.optional(z.boolean()).meta({
    description:
      'Only exists on the following optionally tls-enabled proxies: http, socks, v2ray protocols',
  }),
  'skip-cert-verify': z.optional(z.boolean()),
  'alpn': z.optional(z.array(z.string())),
  'servername': z.optional(z.string()).meta({
    deprecated: true,
    description: 'Only used by v2ray protocols',
  }),
  'sni': z.optional(z.string()),
  'x-clash2singbox-certificate': z.optional(z.array(z.string())),
  'x-clash2singbox-certificate-public-key-sha256': z.optional(z.string()),
})
export const ClashProxyBaseVmessOrVLESS = ClashProxyBaseTLS.extend({
  'uuid': z.string(),
  'network': z.optional(z.enum(['ws', 'h2', 'http', 'grpc', 'tcp'])),
  'ws-opts': z.optional(z.object({
    'path': z.optional(z.string()),
    'headers': z.optional(z.record(z.string(), z.string())),
    'max-early-data': z.optional(z.number()),
    'early-data-header-name': z.optional(z.string()),
    'v2ray-http-upgrade': z.optional(z.boolean()),
    'v2ray-http-upgrade-fast-open': z.optional(z.boolean()),
  })),
  'h2-opts': z.optional(z.object({
    host: z.optional(z.array(z.string())),
    path: z.optional(z.string()),
  })),
  'http-opts': z.optional(z.object({
    method: z.optional(z.string()),
    path: z.optional(z.array(z.string())),
    headers: z.optional(z.record(z.string(), z.array(z.string()))),
  })),
  'grpc-opts': z.optional(z.object({
    'grpc-service-name': z.optional(z.string()),
  })),
})
export const ClashProxyAnyTls = ClashProxyBaseTLS.extend({
  'type': z.literal('anytls'),
  'password': z.string(),
  'idle-session-check-interval': z.optional(z.number()),
  'idle-session-timeout': z.optional(z.number()),
  'min-idle-session': z.optional(z.number()),
})
export const ClashProxyHttp = ClashProxyBaseTLS.extend({
  type: z.literal('http'),
  username: z.optional(z.string()),
  password: z.optional(z.string()),
})
export const ClashProxyHysteria = ClashProxyBaseTLS.extend({
  'type': z.literal('hysteria'),
  'auth-str': z.optional(z.string()),
  'obfs': z.optional(z.string()),
  'protocol': z.enum(['udp', 'wechat-video', 'faketcp']),
  'up': z.string(),
  'down': z.string(),
})
export const ClashProxyHysteria2 = ClashProxyBaseTLS.extend({
  'type': z.literal('hysteria2'),
  'password': z.string(),
  'up': z.optional(z.string()),
  'down': z.optional(z.string()),
  'obfs': z.optional(z.string()),
  'obfs-password': z.optional(z.string()),
  'ports': z.optional(z.string()),
  'fingerprint': z.optional(z.string()),
  'client-fingerprint': z.optional(z.string()),
  'reality-opts': z.optional(z.object({
    'public-key': z.string(),
    'short-id': z.string(),
  })),
  'ech-opts': z.optional(z.object({
    enable: z.boolean(),
    config: z.string(),
  })),
  'tfo': z.optional(z.boolean()),
  'mptcp': z.optional(z.boolean()),
  'interface-name': z.optional(z.string()),
  'routing-mark': z.optional(z.number()),
  'certificate': z.optional(z.string()),
})
export const ClashProxySocks5 = ClashProxyBaseTLS.extend({
  type: z.literal('socks5'),
  username: z.optional(z.string()),
  password: z.optional(z.string()),
})
export const ClashProxySSH = ClashProxy.extend({
  'type': z.literal('ssh'),
  'username': z.string(),
  'password': z.optional(z.string()),
  'private-key': z.optional(z.string()),
  'private-key-passphrase': z.optional(z.string()),
  'host-key': z.optional(z.array(z.string())),
  'host-key-algorithms': z.optional(z.array(z.string())),
  'interface-name': z.optional(z.string()),
  'routing-mark': z.optional(z.number()),
  'tfo': z.optional(z.boolean()),
  'mptcp': z.optional(z.boolean()),
  'dialer-proxy': z.optional(z.string()),
})
export const ClashProxyShadowsocks = ClashProxy.extend({
  'type': z.literal('ss'),
  'cipher': z.enum([
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
  'password': z.string(),
  'plugin': z.optional(z.enum(['obfs', 'v2ray-plugin'])),
  'plugin-opts': z.optional(z.object({
    mode: z.enum(['http', 'tls', 'websocket']),
    tls: z.optional(z.boolean()),
    host: z.optional(z.string()),
    path: z.optional(z.string()),
    mux: z.optional(z.boolean()),
  })),
  'udp-over-tcp': z.optional(z.boolean()),
  'udp-over-tcp-version': z.optional(z.union([z.literal(1), z.literal(2)])),
})
export const ClashProxyTrojan = ClashProxyBaseTLS.extend({
  type: z.literal('trojan'),
  password: z.string(),
})
export const ClashProxyTUIC = ClashProxyBaseTLS.extend({
  'type': z.literal('tuic'),
  'uuid': z.string(),
  'password': z.optional(z.string()),
  'heartbeat-interval': z.optional(z.number()),
  'reduce-rtt': z.optional(z.boolean()),
  'udp-relay-mode': z.optional(z.enum(['native', 'quic'])),
  'congestion-controller': z.optional(z.enum(['cubic', 'new_reno', 'bbr'])),
  'udp-over-stream': z.optional(z.boolean()),
})
export const ClashProxyVmess = ClashProxyBaseVmessOrVLESS.extend({
  type: z.literal('vmess'),
  // Temporary workaround
  alterId: z.coerce.number(),
  cipher: z.enum(['aes-128-gcm', 'chacha20-poly1305', 'auto', 'none', 'zero']),
})
export const ClashProxyVLESS = ClashProxyBaseVmessOrVLESS.extend({
  'type': z.literal('vless'),
  'flow': z.optional(z.string()),
  'security': z.optional(z.enum(['tls', 'reality', 'none'])),
  'encryption': z.optional(z.string()),
  'client-fingerprint': z.optional(z.string()),
  'skip-cert-verify': z.optional(z.boolean()),
  'udp': z.optional(z.boolean()),
  'tfo': z.optional(z.boolean()),
  'mptcp': z.optional(z.boolean()),
  'interface-name': z.optional(z.string()),
  'routing-mark': z.optional(z.number()),
  'fingerprint': z.optional(z.string()),
  'reality-opts': z.optional(z.object({
    'public-key': z.string(),
    'short-id': z.string(),
    'spider-x': z.optional(z.string()),
  })),
  'ech-opts': z.optional(z.object({
    'enable': z.boolean(),
    'config': z.optional(z.string()),
    'query-server-name': z.optional(z.string()),
  })),
  'client-version': z.optional(z.string()),
}).passthrough()
export const ClashProxies = z.discriminatedUnion('type', [
  ClashProxyAnyTls,
  ClashProxyHttp,
  ClashProxyHysteria,
  ClashProxyHysteria2,
  ClashProxyShadowsocks,
  ClashProxySocks5,
  ClashProxySSH,
  ClashProxyTrojan,
  ClashProxyTUIC,
  ClashProxyVmess,
  ClashProxyVLESS,
])
// ClashProxyRaw: accepts any object with at least name, server, port, type
// Used for lenient parsing - unknown types are skipped with warnings
const ClashProxyRaw = z.object({
  name: z.string(),
  server: z.string(),
  port: z.number(),
  type: z.string(),
}).passthrough()

export const Clash = z.object({
  proxies: z.array(ClashProxyRaw),
})

const SingboxOutboundCommonDomainResolver = z.object({
  server: z.string(),
  strategy: z.optional(
    z.enum(['prefer_ipv4', 'prefer_ipv6', 'ipv4_only', 'ipv6_only']),
  ),
})
export const SingboxOutboundCommonTlsTransport = z.object({
  enabled: z.boolean(),
  disable_sni: z.optional(z.boolean()),
  server_name: z.optional(z.string()),
  insecure: z.optional(z.boolean()),
  alpn: z.optional(z.array(z.string())),
  certificate: z.optional(z.array(z.string())),
  certificate_public_key_sha256: z.optional(z.string()),
})
const SingboxOutboundCommonVmessOrVLESSTransportGrpc = z.object({
  type: z.literal('grpc'),
  service_name: z.optional(z.string()),
})
const SingboxOutboundCommonVmessOrVLESSTransportCommonHttp = z.object({
  host: z.optional(z.array(z.string())),
  path: z.optional(z.string()),
  method: z.optional(z.string()),
  headers: z.optional(z.record(z.string(), z.string())),
})
const SingboxOutboundCommonVmessOrVLESSTransportHttp
  = SingboxOutboundCommonVmessOrVLESSTransportCommonHttp.extend({
    type: z.literal('http'),
  })
const SingboxOutboundCommonVmessOrVLESSTransportHttpUpgrade
  = SingboxOutboundCommonVmessOrVLESSTransportCommonHttp.extend({
    type: z.literal('httpupgrade'),
  })
const SingboxOutboundCommonVmessOrVLESSTransportWebSocket
  = SingboxOutboundCommonVmessOrVLESSTransportCommonHttp.extend({
    type: z.literal('ws'),
    max_early_data: z.optional(z.number()),
    early_data_header_name: z.optional(z.string()),
  })
export const SingboxOutboundCommonVmessOrVLESSTransport = z.discriminatedUnion(
  'type',
  [
    SingboxOutboundCommonVmessOrVLESSTransportGrpc,
    SingboxOutboundCommonVmessOrVLESSTransportHttp,
    SingboxOutboundCommonVmessOrVLESSTransportHttpUpgrade,
    SingboxOutboundCommonVmessOrVLESSTransportWebSocket,
  ],
)
const SingboxOutbound = z.object({
  tag: z.string(),
  server: z.string(),
  server_port: z.number(),
  network: z.optional(z.enum(['tcp', 'udp', 'tcp,udp'])),
  domain_resolver: z.optional(SingboxOutboundCommonDomainResolver),
})
const SingboxOutboundBaseTLS = SingboxOutbound.extend({
  tls: z.optional(SingboxOutboundCommonTlsTransport),
})
export const SingboxOutboundAnyTls = SingboxOutboundBaseTLS.extend({
  type: z.literal('anytls'),
  password: z.string(),
  idle_session_check_interval: z.optional(z.string()),
  idle_session_timeout: z.optional(z.string()),
  min_idle_session: z.optional(z.number()),
  tls: SingboxOutboundCommonTlsTransport,
})
export const SingboxOutboundHttp = SingboxOutboundBaseTLS.extend({
  type: z.literal('http'),
  username: z.optional(z.string()),
  password: z.optional(z.string()),
})
export const SingboxOutboundHysteria = SingboxOutboundBaseTLS.extend({
  type: z.literal('hysteria'),
  up: z.string(),
  down: z.string(),
  obfs: z.optional(z.string()),
  auth_str: z.optional(z.string()),
  tls: SingboxOutboundCommonTlsTransport,
})
export const SingboxOutboundHysteria2 = SingboxOutbound.extend({
  type: z.literal('hysteria2'),
  server_ports: z.optional(z.array(z.string())),
  up_mbps: z.optional(z.number()),
  down_mbps: z.optional(z.number()),
  password: z.optional(z.string()),
  obfs: z.optional(z.object({
    type: z.string(),
    password: z.string(),
  })),
  tls: z.optional(SingboxOutboundCommonTlsTransport.extend({
    reality: z.optional(z.object({
      enabled: z.boolean(),
      public_key: z.string(),
      short_id: z.string(),
    })),
    ech: z.optional(z.object({
      enabled: z.boolean(),
      config: z.string(),
    })),
    utls: z.optional(z.object({
      enabled: z.boolean(),
      fingerprint: z.string(),
    })),
  })),
  tcp_fast_open: z.optional(z.boolean()),
  tcp_multi_path: z.optional(z.boolean()),
  bind_interface: z.optional(z.string()),
  routing_mark: z.optional(z.number()),
})
export const SingboxOutboundSelector = z.object({
  type: z.literal('selector'),
  tag: z.string(),
  outbounds: z.array(z.string()),
  default: z.optional(z.string()),
})
export const SingboxOutboundURLTest = z.object({
  type: z.literal('urltest'),
  tag: z.string(),
  outbounds: z.array(z.string()),
  url: z.optional(z.string()),
  interval: z.optional(z.string()),
  tolerance: z.optional(z.number()),
  idle_timeout: z.optional(z.string()),
  interrupt_exist_connections: z.optional(z.boolean()),
})
export const SingboxOutboundShadowsocks = SingboxOutbound.extend({
  type: z.literal('shadowsocks'),
  method: z.enum([
    '2022-blake3-aes-128-gcm',
    '2022-blake3-aes-256-gcm',
    '2022-blake3-chacha20-poly1305',
    'none',
    'aes-128-gcm',
    'aes-192-gcm',
    'aes-256-gcm',
    'chacha20-ietf-poly1305',
    'xchacha20-ietf-poly1305',
    'aes-128-ctr',
    'aes-192-ctr',
    'aes-256-ctr',
    'aes-128-cfb',
    'aes-192-cfb',
    'aes-256-cfb',
    'rc4-md5',
    'chacha20-ietf',
    'xchacha20',
  ]),
  password: z.string(),
  plugin: z.optional(z.string()),
  plugin_opts: z.optional(z.string()),
  udp_over_tcp: z.optional(z.object({
    enabled: z.boolean(),
    version: z.optional(z.union([z.literal(1), z.literal(2)])),
  })),
})
export const SingboxOutboundSocks = SingboxOutbound.extend({
  type: z.literal('socks'),
  username: z.optional(z.string()),
  password: z.optional(z.string()),
})
export const SingboxOutboundSSH = SingboxOutbound.extend({
  type: z.literal('ssh'),
  user: z.string(),
  password: z.optional(z.string()),
  private_key: z.optional(z.string()),
  private_key_path: z.optional(z.string()),
  private_key_passphrase: z.optional(z.string()),
  host_key: z.optional(z.array(z.string())),
  host_key_algorithms: z.optional(z.array(z.string())),
  client_version: z.optional(z.string()),
  detour: z.optional(z.string()),
  bind_interface: z.optional(z.string()),
  routing_mark: z.optional(z.number()),
  tcp_fast_open: z.optional(z.boolean()),
  tcp_multi_path: z.optional(z.boolean()),
})
export const SingboxOutboundTrojan = SingboxOutboundBaseTLS.extend({
  type: z.literal('trojan'),
  password: z.string(),
})
export const SingboxOutboundTUIC = SingboxOutbound.extend({
  type: z.literal('tuic'),
  uuid: z.string(),
  password: z.optional(z.string()),
  congestion_control: z.optional(z.enum(['cubic', 'new_reno', 'bbr'])),
  udp_relay_mode: z.optional(z.enum(['native', 'quic'])),
  udp_over_stream: z.optional(z.boolean()),
  zero_rtt_handshake: z.optional(z.boolean()),
  heartbeat: z.optional(z.string()),
  tls: SingboxOutboundCommonTlsTransport,
})
export const SingboxOutboundVmess = SingboxOutboundBaseTLS.extend({
  type: z.literal('vmess'),
  uuid: z.string(),
  security: z.optional(
    z.enum(['auto', 'none', 'zero', 'aes-128-gcm', 'chacha20-poly1305']),
  ),
  alter_id: z.optional(z.number()),
  transport: z.optional(SingboxOutboundCommonVmessOrVLESSTransport),
})
export const SingboxOutboundVLESS = SingboxOutboundBaseTLS.extend({
  type: z.literal('vless'),
  uuid: z.string(),
  flow: z.optional(z.string()),
  transport: z.optional(SingboxOutboundCommonVmessOrVLESSTransport),
})
export const SingboxOutbounds = z.discriminatedUnion('type', [
  SingboxOutboundAnyTls,
  SingboxOutboundHttp,
  SingboxOutboundHysteria,
  SingboxOutboundHysteria2,
  SingboxOutboundShadowsocks,
  SingboxOutboundSocks,
  SingboxOutboundSSH,
  SingboxOutboundTrojan,
  SingboxOutboundTUIC,
  SingboxOutboundVmess,
  SingboxOutboundVLESS,
])
