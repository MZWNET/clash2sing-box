import {
  convert,
  DirectPipeline,
  OpenVPNPipeline,
  ShadowsocksPipeline,
  SnellPipeline,
  TailscalePipeline,
  WireGuardPipeline,
} from '../src/index.ts'

describe('direct pipeline', () => {
  it('converts a direct proxy, which carries no server or port', () => {
    const result = DirectPipeline.parse({ type: 'direct', name: 'direct-out' })

    expect(result).toEqual({ type: 'direct', tag: 'direct-out' })
  })

  it('carries dial fields through, but never a network field', () => {
    const result = DirectPipeline.parse({
      type: 'direct',
      name: 'direct-out',
      'interface-name': 'en0',
      'routing-mark': 100,
      udp: false,
    })

    expect(result.bind_interface).toBe('en0')
    expect(result.routing_mark).toBe(100)
    // The direct outbound has no `network` field; sing-box rejects unknown keys.
    expect(result).not.toHaveProperty('network')
  })
})

describe('snell pipeline', () => {
  const base = { type: 'snell' as const, name: 'snell-01', server: '1.2.3.4', port: 443, psk: 'secret' }

  it('converts version 4', () => {
    const result = SnellPipeline.parse({ ...base, version: 4, reuse: true })

    expect(result).toEqual({
      type: 'snell',
      tag: 'snell-01',
      server: '1.2.3.4',
      server_port: 443,
      version: 4,
      psk: 'secret',
      reuse: true,
    })
  })

  it('converts version 4 http obfuscation', () => {
    const result = SnellPipeline.parse({ ...base, version: 4, 'obfs-opts': { mode: 'http', host: 'bing.com' } })

    expect(result.obfs_mode).toBe('http')
    expect(result.obfs_host).toBe('bing.com')
  })

  // sing-box implements versions 4 and 6; mihomo speaks 1-5, so only 4 overlaps.
  it.each([1, 2, 3, 5])('reports version %i as unsupported', version => {
    const result = SnellPipeline.safeParse({ ...base, version })

    expect(result.success).toBe(false)
    expect(result.error?.issues[0]?.message).toContain('Snell versions 4 and 6')
  })

  it('reports an obfs mode sing-box cannot express', () => {
    const result = SnellPipeline.safeParse({ ...base, version: 4, 'obfs-opts': { mode: 'tls' } })

    expect(result.success).toBe(false)
    expect(result.error?.issues[0]?.message).toContain('obfs mode "tls"')
  })
})

describe('shadowsocks + shadow-tls', () => {
  const proxy = {
    type: 'ss' as const,
    name: 'ss-stls',
    server: '1.2.3.4',
    port: 443,
    cipher: '2022-blake3-aes-128-gcm' as const,
    password: 'inner-password',
    plugin: 'shadow-tls' as const,
    'client-fingerprint': 'chrome',
    'plugin-opts': { host: 'cloud.tencent.com', password: 'stls-password', version: 3 },
  }

  it('splits one Clash proxy into an inner outbound plus a ShadowTLS shell', () => {
    const { outbound, shadowTls } = ShadowsocksPipeline.parse(proxy)

    // The inner outbound reaches the server through the shell, so it has no address.
    expect(outbound.server).toBeUndefined()
    expect(outbound.server_port).toBeUndefined()
    expect(outbound.detour).toBe('ss-stls-shadowtls')
    expect(outbound.method).toBe('2022-blake3-aes-128-gcm')
    expect(outbound.password).toBe('inner-password')
    // The plugin is not passed through as a Shadowsocks plugin.
    expect(outbound.plugin).toBeUndefined()

    expect(shadowTls).toEqual({
      type: 'shadowtls',
      tag: 'ss-stls-shadowtls',
      server: '1.2.3.4',
      server_port: 443,
      version: 3,
      password: 'stls-password',
      tls: {
        enabled: true,
        server_name: 'cloud.tencent.com',
        utls: { enabled: true, fingerprint: 'chrome' },
      },
    })
  })

  it('offers only the inner outbound in proxy groups, never the bare shell', () => {
    const { config } = convert({ proxies: [proxy] })

    const outbounds = config.outbounds!
    expect(outbounds.map(entry => entry.tag)).toContain('ss-stls-shadowtls')

    const selector = outbounds.find(entry => entry.type === 'selector')!
    const urltest = outbounds.find(entry => entry.type === 'urltest')!
    // Selecting a bare ShadowTLS shell would give a tunnel with nothing inside it.
    expect(selector.outbounds).not.toContain('ss-stls-shadowtls')
    expect(urltest.outbounds).toEqual(['ss-stls'])
  })

  it('reports a ShadowTLS version sing-box does not implement', () => {
    const result = ShadowsocksPipeline.safeParse({ ...proxy, 'plugin-opts': { version: 4 } })

    expect(result.success).toBe(false)
    expect(result.error?.issues[0]?.message).toContain('ShadowTLS version 4')
  })
})

describe('wireguard pipeline', () => {
  const base = {
    type: 'wireguard' as const,
    name: 'wg-01',
    'private-key': 'cHJpdmF0ZS1rZXk=',
    ip: '10.0.0.2',
    server: '1.2.3.4',
    port: 51820,
    'public-key': 'cHVibGljLWtleQ==',
  }

  it('converts to an endpoint, since sing-box removed the WireGuard outbound in 1.13.0', () => {
    const result = WireGuardPipeline.parse(base)

    expect(result.type).toBe('wireguard')
    expect(result.tag).toBe('wg-01')
    expect(result.private_key).toBe('cHJpdmF0ZS1rZXk=')
    expect(result.peers).toEqual([
      {
        address: '1.2.3.4',
        port: 51820,
        public_key: 'cHVibGljLWtleQ==',
        allowed_ips: ['0.0.0.0/0', '::/0'],
      },
    ])
  })

  it('adds a CIDR prefix when the address has none', () => {
    expect(WireGuardPipeline.parse(base).address).toEqual(['10.0.0.2/32'])
    expect(WireGuardPipeline.parse({ ...base, ip: '10.0.0.2/24', ipv6: 'fd00::2' }).address).toEqual([
      '10.0.0.2/24',
      'fd00::2/128',
    ])
  })

  it('decodes a base64 reserved value into bytes', () => {
    // "AQID" is 0x01 0x02 0x03.
    const result = WireGuardPipeline.parse({ ...base, reserved: 'AQID' })

    expect(result.peers?.[0]?.reserved).toEqual([1, 2, 3])
  })

  it('prefers an explicit peers list over the single-peer form', () => {
    const result = WireGuardPipeline.parse({
      ...base,
      peers: [
        { server: '5.6.7.8', port: 1234, 'public-key': 'cGVlci1vbmU=', 'allowed-ips': ['10.0.0.0/8'] },
        { server: '9.10.11.12', port: 5678, 'public-key': 'cGVlci10d28=' },
      ],
    })

    expect(result.peers).toHaveLength(2)
    expect(result.peers?.[0]?.allowed_ips).toEqual(['10.0.0.0/8'])
    expect(result.peers?.[1]?.public_key).toBe('cGVlci10d28=')
  })

  it.each([
    [{ ip: undefined, ipv6: undefined }, '"ip" or "ipv6"'],
    [{ 'public-key': undefined }, '"public-key" or a "peers" list'],
  ])('reports missing required WireGuard fields', (override, expected) => {
    const result = WireGuardPipeline.safeParse({ ...base, ...override })

    expect(result.success).toBe(false)
    expect(result.error?.issues[0]?.message).toContain(expected)
  })

  it('lands in the top-level endpoints section and is selectable', () => {
    const { config } = convert({ proxies: [base] })

    const endpoints = config.endpoints!
    expect(endpoints).toHaveLength(1)
    expect(endpoints[0]?.tag).toBe('wg-01')
    // It is a usable proxy target, so groups reference it.
    const selector = config.outbounds!.find(entry => entry.type === 'selector')!
    expect(selector.outbounds).toContain('wg-01')
  })

  it('omits the endpoints section entirely when no WireGuard proxy is present', () => {
    const { config } = convert({
      proxies: [{ name: 'ss', type: 'ss', server: '1.2.3.4', port: 1, cipher: 'aes-256-gcm', password: 'p' }],
    })

    expect(config.endpoints).toBeUndefined()
  })
})

describe('tailscale pipeline', () => {
  it('converts to an endpoint with no server address of its own', () => {
    const result = TailscalePipeline.parse({
      type: 'tailscale',
      name: 'ts-01',
      'auth-key': 'tskey-auth-xxx',
      'control-url': 'https://headscale.example.com',
      'state-dir': '/var/lib/ts',
      ephemeral: true,
      hostname: 'my-node',
      'accept-routes': true,
      'exit-node': 'auto:any',
      'exit-node-allow-lan-access': true,
    })

    expect(result).toEqual({
      type: 'tailscale',
      tag: 'ts-01',
      auth_key: 'tskey-auth-xxx',
      control_url: 'https://headscale.example.com',
      state_directory: '/var/lib/ts',
      ephemeral: true,
      hostname: 'my-node',
      accept_routes: true,
      exit_node: 'auto:any',
      exit_node_allow_lan_access: true,
    })
  })

  it('never carries a network field, even with udp disabled', () => {
    const result = TailscalePipeline.parse({ type: 'tailscale', name: 'ts', udp: false })

    expect(result).not.toHaveProperty('network')
  })

  it('lands in the endpoints section and is selectable', () => {
    const { config } = convert({ proxies: [{ type: 'tailscale', name: 'ts' }] })

    expect(config.endpoints?.map(entry => entry.tag)).toEqual(['ts'])
    const selector = config.outbounds!.find(entry => entry.type === 'selector')!
    expect(selector.outbounds).toContain('ts')
  })
})

describe('openvpn pipeline', () => {
  const base = {
    type: 'openvpn' as const,
    name: 'ovpn-01',
    server: '1.2.3.4',
    ca: '-----BEGIN CERTIFICATE-----\nCA\n-----END CERTIFICATE-----',
    username: 'user',
    password: 'pass',
  }

  it('defaults the port to 1194, matching mihomo and OpenVPN', () => {
    expect(OpenVPNPipeline.parse(base).server_port).toBe(1194)
    expect(OpenVPNPipeline.parse({ ...base, port: 443 }).server_port).toBe(443)
  })

  it('maps inline PEM onto the TLS certificate fields', () => {
    const result = OpenVPNPipeline.parse({
      ...base,
      cert: '-----BEGIN CERTIFICATE-----\nCERT\n-----END CERTIFICATE-----',
      key: '-----BEGIN PRIVATE KEY-----\nKEY\n-----END PRIVATE KEY-----',
    })

    expect(result.tls.certificate).toEqual([base.ca])
    expect(result.tls.client_certificate?.[0]).toContain('CERT')
    expect(result.tls.client_key?.[0]).toContain('KEY')
  })

  it('takes the transport protocol from proto, not from udp', () => {
    expect(OpenVPNPipeline.parse({ ...base, proto: 'tcp' }).network).toBe('tcp')
    // `udp: false` narrows other protocols to TCP, but here it must not touch the transport.
    expect(OpenVPNPipeline.parse({ ...base, proto: 'udp', udp: false }).network).toBe('udp')
  })

  it.each([
    ['tls-crypt-v2', 'tls_crypt_v2'],
    ['tls-crypt', 'tls_crypt'],
    ['tls-auth', 'tls_auth'],
  ] as const)('wraps the control channel from %s', (clashKey, singboxType) => {
    const result = OpenVPNPipeline.parse({ ...base, [clashKey]: 'KEYDATA' })

    expect(result.tls.control_wrap?.type).toBe(singboxType)
    expect(result.tls.control_wrap?.key).toEqual(['KEYDATA'])
  })

  it('only passes key-direction values sing-box can express', () => {
    expect(
      OpenVPNPipeline.parse({ ...base, 'tls-auth': 'K', 'key-direction': 'client' }).tls.control_wrap?.direction,
    ).toBe('client')
    // mihomo's default "bidirectional" has no sing-box equivalent.
    expect(
      OpenVPNPipeline.parse({ ...base, 'tls-auth': 'K', 'key-direction': 'bidirectional' }).tls.control_wrap?.direction,
    ).toBeUndefined()
  })

  it('treats the legacy cipher as the data-cipher fallback', () => {
    expect(OpenVPNPipeline.parse({ ...base, cipher: 'AES-128-GCM' }).data_ciphers_fallback).toBe('AES-128-GCM')
    // An explicit fallback wins.
    expect(
      OpenVPNPipeline.parse({ ...base, cipher: 'AES-128-GCM', 'data-ciphers-fallback': 'AES-256-CBC' })
        .data_ciphers_fallback,
    ).toBe('AES-256-CBC')
  })

  it('converts second-based timers to duration strings', () => {
    const result = OpenVPNPipeline.parse({ ...base, ping: 10, 'ping-restart': 120, 'handshake-timeout': 60 })

    expect(result.ping_interval).toBe('10s')
    expect(result.ping_restart).toBe('120s')
    expect(result.handshake_window).toBe('60s')
  })

  it('reports TAP devices, which sing-box cannot provide', () => {
    const result = OpenVPNPipeline.safeParse({ ...base, dev: 'tap' })

    expect(result.success).toBe(false)
    expect(result.error?.issues[0]?.message).toContain('OpenVPN device "tap"')
  })
})
