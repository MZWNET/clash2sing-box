import type {
  Clash,
  ClashProxyAnyTls,
  ClashProxyHttp,
  ClashProxyHysteria,
  ClashProxyHysteria2,
  ClashProxyShadowsocks,
  ClashProxySocks5,
  ClashProxySSH,
  ClashProxyTrojan,
  ClashProxyTUIC,
  ClashProxyVLESS,
  ClashProxyVmess,
} from '../src/index.ts'
import type { z } from 'zod'

type AnyTlsProxy = z.infer<typeof ClashProxyAnyTls>
type HttpProxy = z.infer<typeof ClashProxyHttp>
type HysteriaProxy = z.infer<typeof ClashProxyHysteria>
type Hysteria2Proxy = z.infer<typeof ClashProxyHysteria2>
type ShadowsocksProxy = z.infer<typeof ClashProxyShadowsocks>
type Socks5Proxy = z.infer<typeof ClashProxySocks5>
type SSHProxy = z.infer<typeof ClashProxySSH>
type TrojanProxy = z.infer<typeof ClashProxyTrojan>
type TUICProxy = z.infer<typeof ClashProxyTUIC>
type VmessProxy = z.infer<typeof ClashProxyVmess>
type VlessProxy = z.infer<typeof ClashProxyVLESS>
type ClashConfig = z.infer<typeof Clash>

// =============================================================================
// AnyTLS
// =============================================================================

export const minimalAnyTlsProxy: AnyTlsProxy = {
  type: 'anytls',
  name: 'anytls-01',
  server: '198.51.100.1',
  port: 443,
  password: 'test-password-123',
}

export const fullAnyTlsProxy: AnyTlsProxy = {
  type: 'anytls',
  name: 'anytls-02',
  server: '203.0.113.10',
  port: 8443,
  password: 'secure-password-456',
  udp: true,
  'ip-version': 'dual',
  tls: true,
  'skip-cert-verify': false,
  alpn: ['h2', 'http/1.1'],
  sni: 'example.com',
  'x-clash2singbox-certificate': ['-----BEGIN CERTIFICATE-----\nMIIBkTCB+wIJAL...\n-----END CERTIFICATE-----'],
  'x-clash2singbox-certificate-public-key-sha256': 'sha256:abcdef1234567890',
  'idle-session-check-interval': 60,
  'idle-session-timeout': 300,
  'min-idle-session': 2,
}

// =============================================================================
// HTTP
// =============================================================================

export const minimalHttpProxy: HttpProxy = {
  type: 'http',
  name: 'http-01',
  server: '198.51.100.2',
  port: 8080,
}

export const fullHttpProxy: HttpProxy = {
  type: 'http',
  name: 'http-02',
  server: '203.0.113.20',
  port: 3128,
  username: 'proxy-user',
  password: 'proxy-pass',
  udp: false,
  'ip-version': 'ipv4',
  tls: true,
  'skip-cert-verify': true,
  alpn: ['h2'],
  sni: 'proxy.example.com',
  'x-clash2singbox-certificate': ['-----BEGIN CERTIFICATE-----\nMIIBkTCB+wIJAL...\n-----END CERTIFICATE-----'],
  'x-clash2singbox-certificate-public-key-sha256': 'sha256:deadbeef12345678',
}

// =============================================================================
// Hysteria
// =============================================================================

export const minimalHysteriaProxy: HysteriaProxy = {
  type: 'hysteria',
  name: 'hysteria-01',
  server: '198.51.100.3',
  port: 36712,
  protocol: 'udp',
  up: '50 Mbps',
  down: '200 Mbps',
}

export const fullHysteriaProxy: HysteriaProxy = {
  type: 'hysteria',
  name: 'hysteria-02',
  server: '203.0.113.30',
  port: 443,
  protocol: 'udp',
  up: '100 Mbps',
  down: '500 Mbps',
  'auth-str': 'hysteria-auth-token',
  obfs: 'salamander',
  udp: true,
  'ip-version': 'ipv6-prefer',
  tls: true,
  'skip-cert-verify': false,
  alpn: ['h3'],
  sni: 'hysteria.example.com',
  'x-clash2singbox-certificate': ['-----BEGIN CERTIFICATE-----\nMIIBkTCB+wIJAL...\n-----END CERTIFICATE-----'],
  'x-clash2singbox-certificate-public-key-sha256': 'sha256:cafebabe12345678',
}

// =============================================================================
// Hysteria2
// =============================================================================

export const minimalHysteria2Proxy: Hysteria2Proxy = {
  type: 'hysteria2',
  name: 'hysteria2-01',
  server: '198.51.100.4',
  port: 443,
  password: 'hy2-password-123',
}

export const fullHysteria2Proxy: Hysteria2Proxy = {
  type: 'hysteria2',
  name: 'hysteria2-02',
  server: '203.0.113.40',
  port: 8443,
  password: 'hy2-secure-password',
  up: '80 Mbps',
  down: '400 Mbps',
  obfs: 'salamander',
  'obfs-password': 'obfs-secret',
  ports: '10000-20000',
  fingerprint: 'chrome',
  'client-fingerprint': 'firefox',
  'reality-opts': {
    'public-key': 'aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789',
    'short-id': 'abcdef12',
  },
  'ech-opts': {
    enable: true,
    config: 'Y3VzdG9tLWVjaC1jb25maWc=',
  },
  udp: true,
  'ip-version': 'dual',
  tls: true,
  'skip-cert-verify': false,
  alpn: ['h3'],
  sni: 'hy2.example.com',
  'x-clash2singbox-certificate': ['-----BEGIN CERTIFICATE-----\nMIIBkTCB+wIJAL...\n-----END CERTIFICATE-----'],
  'x-clash2singbox-certificate-public-key-sha256': 'sha256:1234567890abcdef',
  tfo: true,
  mptcp: true,
  'interface-name': 'utun0',
  'routing-mark': 100,
  certificate: '-----BEGIN CERTIFICATE-----\nMIIBkTCB+wIJAL...\n-----END CERTIFICATE-----',
}

// =============================================================================
// Shadowsocks
// =============================================================================

export const minimalShadowsocksProxy: ShadowsocksProxy = {
  type: 'ss',
  name: 'ss-01',
  server: '198.51.100.5',
  port: 8388,
  cipher: 'aes-256-gcm',
  password: 'ss-password-123',
}

export const fullShadowsocksProxy: ShadowsocksProxy = {
  type: 'ss',
  name: 'ss-02',
  server: '203.0.113.50',
  port: 443,
  cipher: '2022-blake3-aes-256-gcm',
  password: 'ss-secure-password',
  plugin: 'v2ray-plugin',
  'plugin-opts': {
    mode: 'websocket',
    tls: true,
    host: 'cdn.example.com',
    path: '/ss',
    mux: false,
  },
  udp: true,
  'ip-version': 'ipv4-prefer',
  'udp-over-tcp': true,
  'udp-over-tcp-version': 2,
}

// =============================================================================
// Socks5
// =============================================================================

export const minimalSocks5Proxy: Socks5Proxy = {
  type: 'socks5',
  name: 'socks5-01',
  server: '198.51.100.6',
  port: 1080,
}

export const fullSocks5Proxy: Socks5Proxy = {
  type: 'socks5',
  name: 'socks5-02',
  server: '203.0.113.60',
  port: 1080,
  username: 'socks-user',
  password: 'socks-pass',
  udp: true,
  'ip-version': 'ipv6',
  tls: true,
  'skip-cert-verify': true,
  alpn: ['h2', 'http/1.1'],
  sni: 'socks.example.com',
  'x-clash2singbox-certificate': ['-----BEGIN CERTIFICATE-----\nMIIBkTCB+wIJAL...\n-----END CERTIFICATE-----'],
  'x-clash2singbox-certificate-public-key-sha256': 'sha256:fedcba0987654321',
}

// =============================================================================
// SSH
// =============================================================================

export const minimalSSHProxy: SSHProxy = {
  type: 'ssh',
  name: 'ssh-01',
  server: '198.51.100.7',
  port: 22,
  username: 'root',
}

export const fullSSHProxy: SSHProxy = {
  type: 'ssh',
  name: 'ssh-02',
  server: '203.0.113.70',
  port: 2222,
  username: 'admin',
  password: 'ssh-password',
  'private-key': '-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAA...\n-----END OPENSSH PRIVATE KEY-----',
  'private-key-passphrase': 'key-passphrase',
  'host-key': ['ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA...'],
  'host-key-algorithms': ['ssh-ed25519', 'rsa-sha2-256'],
  'interface-name': 'utun0',
  'routing-mark': 200,
  tfo: true,
  mptcp: false,
  'dialer-proxy': 'socks5-01',
}

// =============================================================================
// Trojan
// =============================================================================

export const minimalTrojanProxy: TrojanProxy = {
  type: 'trojan',
  name: 'trojan-01',
  server: '198.51.100.8',
  port: 443,
  password: 'trojan-password-123',
}

export const fullTrojanProxy: TrojanProxy = {
  type: 'trojan',
  name: 'trojan-02',
  server: '203.0.113.80',
  port: 8443,
  password: 'trojan-secure-password',
  udp: true,
  'ip-version': 'dual',
  tls: true,
  'skip-cert-verify': false,
  alpn: ['h2', 'http/1.1'],
  sni: 'trojan.example.com',
  'x-clash2singbox-certificate': ['-----BEGIN CERTIFICATE-----\nMIIBkTCB+wIJAL...\n-----END CERTIFICATE-----'],
  'x-clash2singbox-certificate-public-key-sha256': 'sha256:abcdefabcdef1234',
}

// =============================================================================
// TUIC
// =============================================================================

export const minimalTUICProxy: TUICProxy = {
  type: 'tuic',
  name: 'tuic-01',
  server: '198.51.100.9',
  port: 443,
  uuid: '12345678-1234-1234-1234-123456789abc',
}

export const fullTUICProxy: TUICProxy = {
  type: 'tuic',
  name: 'tuic-02',
  server: '203.0.113.90',
  port: 8443,
  uuid: 'abcdefab-cdef-abcd-efab-cdefabcdefab',
  password: 'tuic-password',
  'heartbeat-interval': 10,
  'reduce-rtt': true,
  'udp-relay-mode': 'native',
  'congestion-controller': 'bbr',
  'udp-over-stream': true,
  udp: true,
  'ip-version': 'ipv4',
  tls: true,
  'skip-cert-verify': false,
  alpn: ['h3'],
  sni: 'tuic.example.com',
  'x-clash2singbox-certificate': ['-----BEGIN CERTIFICATE-----\nMIIBkTCB+wIJAL...\n-----END CERTIFICATE-----'],
  'x-clash2singbox-certificate-public-key-sha256': 'sha256:1122334455667788',
}

// =============================================================================
// VMess
// =============================================================================

export const minimalVmessProxy: VmessProxy = {
  type: 'vmess',
  name: 'vmess-01',
  server: '198.51.100.10',
  port: 443,
  uuid: '12345678-1234-1234-1234-123456789abc',
  alterId: 0,
  cipher: 'auto',
}

export const fullVmessProxy: VmessProxy = {
  type: 'vmess',
  name: 'vmess-02',
  server: '203.0.113.100',
  port: 8443,
  uuid: 'abcdefab-cdef-abcd-efab-cdefabcdefab',
  alterId: 0,
  cipher: 'aes-128-gcm',
  network: 'ws',
  'ws-opts': {
    path: '/vmess',
    headers: {
      Host: 'cdn.example.com',
    },
    'max-early-data': 2048,
    'early-data-header-name': 'Sec-WebSocket-Protocol',
    'v2ray-http-upgrade': false,
    'v2ray-http-upgrade-fast-open': false,
  },
  udp: true,
  'ip-version': 'dual',
  tls: true,
  'skip-cert-verify': false,
  alpn: ['h2', 'http/1.1'],
  servername: 'vmess.example.com',
  sni: 'vmess.example.com',
  'x-clash2singbox-certificate': ['-----BEGIN CERTIFICATE-----\nMIIBkTCB+wIJAL...\n-----END CERTIFICATE-----'],
  'x-clash2singbox-certificate-public-key-sha256': 'sha256:aabbccdd11223344',
}

// =============================================================================
// VLESS
// =============================================================================

export const minimalVlessProxy: VlessProxy = {
  type: 'vless',
  name: 'vless-01',
  server: '198.51.100.11',
  port: 443,
  uuid: '12345678-1234-1234-1234-123456789abc',
}

export const fullVlessProxy: VlessProxy = {
  type: 'vless',
  name: 'vless-02',
  server: '203.0.113.110',
  port: 8443,
  uuid: 'abcdefab-cdef-abcd-efab-cdefabcdefab',
  flow: 'xtls-rprx-vision',
  network: 'grpc',
  'grpc-opts': {
    'grpc-service-name': 'grpc-service',
  },
  udp: true,
  'ip-version': 'ipv6-prefer',
  tls: true,
  'skip-cert-verify': false,
  alpn: ['h2'],
  servername: 'vless.example.com',
  sni: 'vless.example.com',
  'x-clash2singbox-certificate': ['-----BEGIN CERTIFICATE-----\nMIIBkTCB+wIJAL...\n-----END CERTIFICATE-----'],
  'x-clash2singbox-certificate-public-key-sha256': 'sha256:5566778899001122',
}

// =============================================================================
// Clash Config
// =============================================================================

export const minimalClashConfig: ClashConfig = {
  proxies: [
    minimalAnyTlsProxy,
    minimalHttpProxy,
    minimalHysteriaProxy,
    minimalHysteria2Proxy,
    minimalShadowsocksProxy,
    minimalSocks5Proxy,
    minimalSSHProxy,
    minimalTrojanProxy,
    minimalTUICProxy,
    minimalVmessProxy,
    minimalVlessProxy,
  ],
}

// =============================================================================
// Sing-box Config (minimal valid)
// =============================================================================

export const minimalSingboxConfig = {
  outbounds: [
    {
      type: 'anytls' as const,
      tag: 'anytls-01',
      server: '198.51.100.1',
      server_port: 443,
      password: 'test-password-123',
      tls: {
        enabled: true,
        server_name: 'example.com',
      },
    },
    {
      type: 'http' as const,
      tag: 'http-01',
      server: '198.51.100.2',
      server_port: 8080,
    },
    {
      type: 'hysteria' as const,
      tag: 'hysteria-01',
      server: '198.51.100.3',
      server_port: 36712,
      up: '50 Mbps',
      down: '200 Mbps',
      tls: {
        enabled: true,
        server_name: 'hysteria.example.com',
      },
    },
    {
      type: 'hysteria2' as const,
      tag: 'hysteria2-01',
      server: '198.51.100.4',
      server_port: 443,
      password: 'hy2-password-123',
      tls: {
        enabled: true,
        server_name: 'hy2.example.com',
      },
    },
    {
      type: 'shadowsocks' as const,
      tag: 'ss-01',
      server: '198.51.100.5',
      server_port: 8388,
      method: 'aes-256-gcm',
      password: 'ss-password-123',
    },
    {
      type: 'socks' as const,
      tag: 'socks5-01',
      server: '198.51.100.6',
      server_port: 1080,
    },
    {
      type: 'ssh' as const,
      tag: 'ssh-01',
      server: '198.51.100.7',
      server_port: 22,
      user: 'root',
    },
    {
      type: 'trojan' as const,
      tag: 'trojan-01',
      server: '198.51.100.8',
      server_port: 443,
      password: 'trojan-password-123',
      tls: {
        enabled: true,
        server_name: 'trojan.example.com',
      },
    },
    {
      type: 'tuic' as const,
      tag: 'tuic-01',
      server: '198.51.100.9',
      server_port: 443,
      uuid: '12345678-1234-1234-1234-123456789abc',
      tls: {
        enabled: true,
        server_name: 'tuic.example.com',
      },
    },
    {
      type: 'vmess' as const,
      tag: 'vmess-01',
      server: '198.51.100.10',
      server_port: 443,
      uuid: '12345678-1234-1234-1234-123456789abc',
      security: 'auto',
      alter_id: 0,
      tls: {
        enabled: true,
        server_name: 'vmess.example.com',
      },
    },
    {
      type: 'vless' as const,
      tag: 'vless-01',
      server: '198.51.100.11',
      server_port: 443,
      uuid: '12345678-1234-1234-1234-123456789abc',
      tls: {
        enabled: true,
        server_name: 'vless.example.com',
      },
    },
  ],
}
