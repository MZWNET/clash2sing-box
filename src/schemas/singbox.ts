import { z } from 'zod'

const SingboxOutboundCommonDomainResolver = z.object({
  server: z.string(),
  strategy: z.enum(['prefer_ipv4', 'prefer_ipv6', 'ipv4_only', 'ipv6_only']).optional(),
})

/**
 * sing-box's shared "Dial Fields", accepted by every outbound and endpoint.
 * `domain_strategy` is deliberately absent: deprecated in 1.12.0 and removed in 1.14.0,
 * superseded by `domain_resolver`.
 */
const SingboxDialFields = {
  detour: z.string().optional(),
  bind_interface: z.string().optional(),
  routing_mark: z.number().optional(),
  tcp_fast_open: z.boolean().optional(),
  tcp_multi_path: z.boolean().optional(),
  domain_resolver: SingboxOutboundCommonDomainResolver.optional(),
}

/**
 * `network` restricts which networks an outbound serves. It is NOT a dial field: only
 * some outbounds accept it, and sing-box rejects configs carrying unknown keys, so
 * emitting it on (say) `direct` or `http` would break the whole config.
 */
const SingboxNetworkField = {
  network: z.enum(['tcp', 'udp', 'tcp,udp']).optional(),
}

/** Multiplex, supported by the Shadowsocks, Trojan, Vmess and VLESS outbounds. */
export const SingboxMultiplex = z.object({
  enabled: z.boolean(),
  protocol: z.enum(['smux', 'yamux', 'h2mux']).optional(),
  max_connections: z.number().optional(),
  min_streams: z.number().optional(),
  max_streams: z.number().optional(),
  padding: z.boolean().optional(),
  brutal: z
    .object({
      enabled: z.boolean(),
      up_mbps: z.number().optional(),
      down_mbps: z.number().optional(),
    })
    .optional(),
})

/**
 * TLS transport shared by every outbound that can carry TLS.
 *
 * `reality`/`ech`/`utls` belong here rather than on a single protocol: any TLS-capable
 * outbound may use them, and VLESS in particular needs REALITY to produce a usable config.
 */
export const SingboxOutboundCommonTlsTransport = z.object({
  enabled: z.boolean(),
  disable_sni: z.boolean().optional(),
  server_name: z.string().optional(),
  insecure: z.boolean().optional(),
  alpn: z.array(z.string()).optional(),
  certificate: z.array(z.string()).optional(),
  certificate_public_key_sha256: z.string().optional(),
  reality: z
    .object({
      enabled: z.boolean(),
      public_key: z.string(),
      short_id: z.string().optional(),
    })
    .optional(),
  ech: z
    .object({
      enabled: z.boolean(),
      config: z.string().optional(),
    })
    .optional(),
  utls: z
    .object({
      enabled: z.boolean(),
      fingerprint: z.string(),
    })
    .optional(),
})

const SingboxOutboundCommonVmessOrVLESSTransportGrpc = z.object({
  type: z.literal('grpc'),
  service_name: z.string().optional(),
})
const SingboxOutboundCommonVmessOrVLESSTransportCommonHttp = z.object({
  host: z.array(z.string()).optional(),
  path: z.string().optional(),
  method: z.string().optional(),
  headers: z.record(z.string(), z.string()).optional(),
})
const SingboxOutboundCommonVmessOrVLESSTransportHttp = SingboxOutboundCommonVmessOrVLESSTransportCommonHttp.extend({
  type: z.literal('http'),
})
const SingboxOutboundCommonVmessOrVLESSTransportHttpUpgrade =
  SingboxOutboundCommonVmessOrVLESSTransportCommonHttp.extend({
    type: z.literal('httpupgrade'),
  })
const SingboxOutboundCommonVmessOrVLESSTransportWebSocket = SingboxOutboundCommonVmessOrVLESSTransportCommonHttp.extend(
  {
    type: z.literal('ws'),
    max_early_data: z.number().optional(),
    early_data_header_name: z.string().optional(),
  },
)
export const SingboxOutboundCommonVmessOrVLESSTransport = z.discriminatedUnion('type', [
  SingboxOutboundCommonVmessOrVLESSTransportGrpc,
  SingboxOutboundCommonVmessOrVLESSTransportHttp,
  SingboxOutboundCommonVmessOrVLESSTransportHttpUpgrade,
  SingboxOutboundCommonVmessOrVLESSTransportWebSocket,
])

const SingboxOutbound = z.object({
  tag: z.string(),
  server: z.string(),
  server_port: z.number(),
  ...SingboxDialFields,
})
const SingboxOutboundBaseTLS = SingboxOutbound.extend({
  tls: SingboxOutboundCommonTlsTransport.optional(),
})

export const SingboxOutboundAnyTls = SingboxOutboundBaseTLS.extend({
  type: z.literal('anytls'),
  password: z.string(),
  idle_session_check_interval: z.string().optional(),
  idle_session_timeout: z.string().optional(),
  min_idle_session: z.number().optional(),
  tls: SingboxOutboundCommonTlsTransport,
})

export const SingboxOutboundDirect = z.object({
  type: z.literal('direct'),
  tag: z.string(),
  ...SingboxDialFields,
})

export const SingboxOutboundHttp = SingboxOutboundBaseTLS.extend({
  type: z.literal('http'),
  username: z.string().optional(),
  password: z.string().optional(),
})

export const SingboxOutboundHysteria = SingboxOutboundBaseTLS.extend({
  ...SingboxNetworkField,
  type: z.literal('hysteria'),
  up: z.string(),
  down: z.string(),
  obfs: z.string().optional(),
  auth_str: z.string().optional(),
  tls: SingboxOutboundCommonTlsTransport,
})

export const SingboxOutboundHysteria2 = SingboxOutboundBaseTLS.extend({
  ...SingboxNetworkField,
  type: z.literal('hysteria2'),
  server_ports: z.array(z.string()).optional(),
  up_mbps: z.number().optional(),
  down_mbps: z.number().optional(),
  password: z.string().optional(),
  obfs: z
    .object({
      type: z.string(),
      password: z.string(),
    })
    .optional(),
})

export const SingboxOutboundSelector = z.object({
  type: z.literal('selector'),
  tag: z.string(),
  outbounds: z.array(z.string()),
  default: z.string().optional(),
})

export const SingboxOutboundURLTest = z.object({
  type: z.literal('urltest'),
  tag: z.string(),
  outbounds: z.array(z.string()),
  url: z.string().optional(),
  interval: z.string().optional(),
  tolerance: z.number().optional(),
  idle_timeout: z.string().optional(),
  interrupt_exist_connections: z.boolean().optional(),
})

export const SingboxOutboundShadowsocks = z.object({
  type: z.literal('shadowsocks'),
  tag: z.string(),
  // Optional because a Shadowsocks outbound sitting behind ShadowTLS omits them: the
  // ShadowTLS outbound owns the server address and this one reaches it through `detour`.
  server: z.string().optional(),
  server_port: z.number().optional(),
  ...SingboxDialFields,
  ...SingboxNetworkField,
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
  plugin: z.string().optional(),
  plugin_opts: z.string().optional(),
  multiplex: SingboxMultiplex.optional(),
  udp_over_tcp: z
    .object({
      enabled: z.boolean(),
      version: z.union([z.literal(1), z.literal(2)]).optional(),
    })
    .optional(),
})

/**
 * ShadowTLS is a standalone outbound in sing-box: it is a protocol-agnostic TLS
 * masquerade with no encryption of its own, so the inner proxy reaches it via `detour`.
 */
export const SingboxOutboundShadowTLS = SingboxOutbound.extend({
  type: z.literal('shadowtls'),
  version: z.union([z.literal(1), z.literal(2), z.literal(3)]).optional(),
  password: z.string().optional(),
  tls: SingboxOutboundCommonTlsTransport,
})

/** Snell. New in sing-box 1.14.0; only protocol versions 4 and 6 are implemented. */
export const SingboxOutboundSnell = SingboxOutbound.extend({
  ...SingboxNetworkField,
  type: z.literal('snell'),
  version: z.union([z.literal(4), z.literal(6)]).optional(),
  psk: z.string(),
  userkey: z.string().optional(),
  reuse: z.boolean().optional(),
  obfs_mode: z.enum(['none', 'http']).optional(),
  obfs_host: z.string().optional(),
  mode: z.enum(['default', 'unshaped', 'unsafe-raw']).optional(),
})

export const SingboxOutboundSocks = SingboxOutbound.extend({
  ...SingboxNetworkField,
  type: z.literal('socks'),
  username: z.string().optional(),
  password: z.string().optional(),
})

export const SingboxOutboundSSH = SingboxOutbound.extend({
  type: z.literal('ssh'),
  user: z.string(),
  password: z.string().optional(),
  private_key: z.string().optional(),
  private_key_path: z.string().optional(),
  private_key_passphrase: z.string().optional(),
  host_key: z.array(z.string()).optional(),
  host_key_algorithms: z.array(z.string()).optional(),
  client_version: z.string().optional(),
})

export const SingboxOutboundTrojan = SingboxOutboundBaseTLS.extend({
  ...SingboxNetworkField,
  type: z.literal('trojan'),
  password: z.string(),
  multiplex: SingboxMultiplex.optional(),
  transport: SingboxOutboundCommonVmessOrVLESSTransport.optional(),
})

export const SingboxOutboundTUIC = SingboxOutbound.extend({
  ...SingboxNetworkField,
  type: z.literal('tuic'),
  uuid: z.string(),
  password: z.string().optional(),
  congestion_control: z.enum(['cubic', 'new_reno', 'bbr']).optional(),
  udp_relay_mode: z.enum(['native', 'quic']).optional(),
  udp_over_stream: z.boolean().optional(),
  zero_rtt_handshake: z.boolean().optional(),
  heartbeat: z.string().optional(),
  tls: SingboxOutboundCommonTlsTransport,
})

export const SingboxOutboundVmess = SingboxOutboundBaseTLS.extend({
  ...SingboxNetworkField,
  type: z.literal('vmess'),
  uuid: z.string(),
  security: z.enum(['auto', 'none', 'zero', 'aes-128-gcm', 'chacha20-poly1305']).optional(),
  alter_id: z.number().optional(),
  global_padding: z.boolean().optional(),
  authenticated_length: z.boolean().optional(),
  packet_encoding: z.enum(['packetaddr', 'xudp']).optional(),
  multiplex: SingboxMultiplex.optional(),
  transport: SingboxOutboundCommonVmessOrVLESSTransport.optional(),
})

export const SingboxOutboundVLESS = SingboxOutboundBaseTLS.extend({
  ...SingboxNetworkField,
  type: z.literal('vless'),
  uuid: z.string(),
  flow: z.string().optional(),
  packet_encoding: z.enum(['packetaddr', 'xudp']).optional(),
  multiplex: SingboxMultiplex.optional(),
  transport: SingboxOutboundCommonVmessOrVLESSTransport.optional(),
})

export const SingboxOutbounds = z.discriminatedUnion('type', [
  SingboxOutboundAnyTls,
  SingboxOutboundDirect,
  SingboxOutboundHttp,
  SingboxOutboundHysteria,
  SingboxOutboundHysteria2,
  SingboxOutboundShadowsocks,
  SingboxOutboundShadowTLS,
  SingboxOutboundSnell,
  SingboxOutboundSocks,
  SingboxOutboundSSH,
  SingboxOutboundTrojan,
  SingboxOutboundTUIC,
  SingboxOutboundVmess,
  SingboxOutboundVLESS,
])

/**
 * WireGuard moved out of `outbounds` into the top-level `endpoints` section:
 * the outbound was deprecated in sing-box 1.11.0 and removed in 1.13.0.
 */
export const SingboxEndpointWireGuard = z.object({
  type: z.literal('wireguard'),
  tag: z.string(),
  system: z.boolean().optional(),
  name: z.string().optional(),
  mtu: z.number().optional(),
  address: z.array(z.string()),
  private_key: z.string(),
  listen_port: z.number().optional(),
  peers: z
    .array(
      z.object({
        address: z.string().optional(),
        port: z.number().optional(),
        public_key: z.string(),
        pre_shared_key: z.string().optional(),
        allowed_ips: z.array(z.string()).optional(),
        persistent_keepalive_interval: z.number().optional(),
        reserved: z.array(z.number()).optional(),
      }),
    )
    .optional(),
  udp_timeout: z.string().optional(),
  workers: z.number().optional(),
  ...SingboxDialFields,
})

/** Tailscale, added as an endpoint in sing-box 1.12.0. */
export const SingboxEndpointTailscale = z.object({
  type: z.literal('tailscale'),
  tag: z.string(),
  state_directory: z.string().optional(),
  auth_key: z.string().optional(),
  control_url: z.string().optional(),
  ephemeral: z.boolean().optional(),
  hostname: z.string().optional(),
  accept_routes: z.boolean().optional(),
  exit_node: z.string().optional(),
  exit_node_allow_lan_access: z.boolean().optional(),
  advertise_routes: z.array(z.string()).optional(),
  advertise_exit_node: z.boolean().optional(),
  udp_timeout: z.string().optional(),
  ...SingboxDialFields,
})

/** OpenVPN client, added as an endpoint in sing-box 1.14.0. Only TLS mode is emitted. */
export const SingboxEndpointOpenVPNClient = z.object({
  type: z.literal('openvpn-client'),
  tag: z.string(),
  server: z.string(),
  server_port: z.number(),
  // On OpenVPN this selects the transport protocol, unlike the `network` of an outbound.
  network: z.enum(['udp', 'tcp']).optional(),
  username: z.string().optional(),
  password: z.string().optional(),
  tls: z.object({
    certificate: z.array(z.string()).optional(),
    client_certificate: z.array(z.string()).optional(),
    client_key: z.array(z.string()).optional(),
    control_wrap: z
      .object({
        type: z.enum(['tls_auth', 'tls_crypt', 'tls_crypt_v2']),
        key: z.array(z.string()).optional(),
        direction: z.enum(['server', 'client']).optional(),
      })
      .optional(),
  }),
  data_ciphers: z.array(z.string()).optional(),
  data_ciphers_fallback: z.string().optional(),
  auth: z.string().optional(),
  compression_lzo: z.string().optional(),
  mtu: z.number().optional(),
  ping_interval: z.string().optional(),
  ping_restart: z.string().optional(),
  handshake_window: z.string().optional(),
  ...SingboxDialFields,
})

export const SingboxEndpoints = z.discriminatedUnion('type', [
  SingboxEndpointWireGuard,
  SingboxEndpointTailscale,
  SingboxEndpointOpenVPNClient,
])

/** Any outbound that may appear in the generated config, including the group outbounds. */
export type SingboxAnyOutbound =
  | z.infer<typeof SingboxOutbounds>
  | z.infer<typeof SingboxOutboundSelector>
  | z.infer<typeof SingboxOutboundURLTest>

export type SingboxAnyEndpoint = z.infer<typeof SingboxEndpoints>

/**
 * A sing-box config. Only `outbounds` and `endpoints` are interpreted; every other
 * top-level key (`log`, `dns`, `route`, …) is merged through untouched.
 */
export const SingboxConfigSchema = z.looseObject({
  outbounds: z.array(z.unknown()).optional(),
  endpoints: z.array(z.unknown()).optional(),
})

/** The minimum an incoming outbound must have for us to reference it from a group. */
export const SingboxTaggedOutbound = z.looseObject({
  tag: z.string(),
})

/** Top-level keys that identify a file as a sing-box config rather than a Clash one. */
export const SINGBOX_CONFIG_KEYS = ['log', 'dns', 'inbounds', 'outbounds', 'endpoints', 'route'] as const

/** A document is a sing-box config when it carries at least one sing-box-only section. */
export const SingboxConfigProbe = z.looseObject({}).refine(config => SINGBOX_CONFIG_KEYS.some(key => key in config), {
  message: `expected at least one of: ${SINGBOX_CONFIG_KEYS.join(', ')}`,
})

export interface SingboxConfig {
  outbounds?: SingboxAnyOutbound[]
  endpoints?: SingboxAnyEndpoint[]
  [key: string]: unknown
}

export type SingboxOutboundCommonTls = z.infer<typeof SingboxOutboundCommonTlsTransport>
export type SingboxOutboundCommonTransport = z.infer<typeof SingboxOutboundCommonVmessOrVLESSTransport>
export type SingboxMultiplexInput = z.infer<typeof SingboxMultiplex>
