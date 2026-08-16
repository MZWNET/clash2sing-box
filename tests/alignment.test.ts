import {
  AnyTlsPipeline,
  convertDialFields,
  convertMultiplex,
  convertNetwork,
  DirectPipeline,
  HttpPipeline,
  ShadowsocksPipeline,
  Socks5Pipeline,
  SSHPipeline,
  TrojanPipeline,
  TUICPipeline,
  VLESSPipeline,
  VmessPipeline,
} from '../src/index.ts'

describe('convertDialFields', () => {
  it('maps every mihomo dial option onto its sing-box name', () => {
    expect(
      convertDialFields({
        udp: false,
        tfo: true,
        mptcp: true,
        'interface-name': 'utun0',
        'routing-mark': 255,
        'dialer-proxy': 'upstream',
      }),
    ).toEqual({
      detour: 'upstream',
      bind_interface: 'utun0',
      routing_mark: 255,
      tcp_fast_open: true,
      tcp_multi_path: true,
    })
  })

  // `network` is a per-outbound field, not a dial field, so it must not leak in here:
  // sing-box rejects configs carrying unknown keys.
  it('does not emit network, which only some outbounds accept', () => {
    expect(convertDialFields({ udp: false })).not.toHaveProperty('network')
  })
})

describe('convertNetwork', () => {
  it('narrows to tcp only when udp is explicitly disabled', () => {
    expect(convertNetwork({ udp: false })).toBe('tcp')
    expect(convertNetwork({ udp: true })).toBeUndefined()
    expect(convertNetwork({})).toBeUndefined()
  })
})

describe('network is emitted only where sing-box accepts it', () => {
  const udpOff = { udp: false }

  it.each([
    ['socks5', Socks5Pipeline, { type: 'socks5', name: 'p', server: '1.2.3.4', port: 1080 }],
    ['tuic', TUICPipeline, { type: 'tuic', name: 'p', server: '1.2.3.4', port: 443, uuid: 'u' }],
    ['vless', VLESSPipeline, { type: 'vless', name: 'p', server: '1.2.3.4', port: 443, uuid: 'u' }],
  ] as const)('%s carries network', (_name, pipeline, proxy) => {
    expect(pipeline.parse({ ...proxy, ...udpOff }).network).toBe('tcp')
  })

  // These outbounds have no `network` field at all; emitting one would make sing-box
  // reject the whole config.
  it.each([
    ['http', HttpPipeline, { type: 'http', name: 'p', server: '1.2.3.4', port: 8080 }],
    ['ssh', SSHPipeline, { type: 'ssh', name: 'p', server: '1.2.3.4', port: 22, username: 'root' }],
    ['anytls', AnyTlsPipeline, { type: 'anytls', name: 'p', server: '1.2.3.4', port: 443, password: 'pw' }],
    ['direct', DirectPipeline, { type: 'direct', name: 'p' }],
  ] as const)('%s never carries network', (_name, pipeline, proxy) => {
    expect(pipeline.parse({ ...proxy, ...udpOff })).not.toHaveProperty('network')
  })
})

describe('dial fields reach every protocol', () => {
  const dial = { tfo: true, mptcp: true, 'interface-name': 'utun0', 'routing-mark': 255, 'dialer-proxy': 'upstream' }

  const cases = [
    ['tuic', TUICPipeline, { type: 'tuic', name: 't', server: '1.2.3.4', port: 443, uuid: 'u' }],
    [
      'vless',
      VLESSPipeline,
      { type: 'vless', name: 'v', server: '1.2.3.4', port: 443, uuid: 'aaaaaaaa-bbbb-cccc-dddd-111111111111' },
    ],
    ['ssh', SSHPipeline, { type: 'ssh', name: 's', server: '1.2.3.4', port: 22, username: 'root' }],
  ] as const

  it.each(cases)('%s carries dial fields through', (_name, pipeline, proxy) => {
    const result = pipeline.parse({ ...proxy, ...dial })

    expect(result.tcp_fast_open).toBe(true)
    expect(result.tcp_multi_path).toBe(true)
    expect(result.bind_interface).toBe('utun0')
    expect(result.routing_mark).toBe(255)
    expect(result.detour).toBe('upstream')
  })
})

describe('convertMultiplex', () => {
  it('maps smux onto multiplex, keeping the shared protocol names', () => {
    expect(
      convertMultiplex({
        enabled: true,
        protocol: 'yamux',
        'max-connections': 4,
        'min-streams': 8,
        'max-streams': 16,
        padding: true,
      }),
    ).toEqual({
      enabled: true,
      protocol: 'yamux',
      max_connections: 4,
      min_streams: 8,
      max_streams: 16,
      padding: true,
    })
  })

  it('carries brutal bandwidth across unchanged, since both sides count Mbps', () => {
    expect(convertMultiplex({ enabled: true, 'brutal-opts': { enabled: true, up: 50, down: 100 } })?.brutal).toEqual({
      enabled: true,
      up_mbps: 50,
      down_mbps: 100,
    })
  })

  it('drops the mihomo-only statistic and only-tcp options', () => {
    const result = convertMultiplex({ enabled: true, statistic: true, 'only-tcp': true })

    expect(result).toEqual({ enabled: true })
  })

  it.each([undefined, { enabled: false }, {}])('returns undefined for %s', smux => {
    expect(convertMultiplex(smux)).toBeUndefined()
  })
})

describe('multiplex reaches the protocols sing-box supports it on', () => {
  const smux = { enabled: true, protocol: 'h2mux' as const, 'max-connections': 4 }
  const expected = { enabled: true, protocol: 'h2mux', max_connections: 4 }

  it('shadowsocks', () => {
    const { outbound } = ShadowsocksPipeline.parse({
      type: 'ss',
      name: 's',
      server: '1.2.3.4',
      port: 1,
      cipher: 'aes-256-gcm',
      password: 'p',
      smux,
    })
    expect(outbound.multiplex).toEqual(expected)
  })

  it('trojan', () => {
    const result = TrojanPipeline.parse({
      type: 'trojan',
      name: 't',
      server: '1.2.3.4',
      port: 443,
      password: 'p',
      smux,
    })
    expect(result.multiplex).toEqual(expected)
  })

  it('vmess', () => {
    const result = VmessPipeline.parse({
      type: 'vmess',
      name: 'v',
      server: '1.2.3.4',
      port: 443,
      uuid: 'u',
      alterId: 0,
      cipher: 'auto',
      smux,
    })
    expect(result.multiplex).toEqual(expected)
  })

  it('vless', () => {
    const result = VLESSPipeline.parse({ type: 'vless', name: 'v', server: '1.2.3.4', port: 443, uuid: 'u', smux })
    expect(result.multiplex).toEqual(expected)
  })
})

describe('trojan transport', () => {
  const base = { type: 'trojan' as const, name: 't', server: '1.2.3.4', port: 443, password: 'p' }

  // Previously dropped entirely, which produced an unusable config for Trojan over ws/gRPC.
  it('converts ws-opts to a websocket transport', () => {
    const result = TrojanPipeline.parse({
      ...base,
      network: 'ws',
      'ws-opts': { path: '/tj', headers: { Host: 'ws.example.com' } },
    })

    expect(result.transport).toEqual({ type: 'ws', path: '/tj', headers: { Host: 'ws.example.com' } })
  })

  it('converts grpc-opts to a gRPC transport', () => {
    const result = TrojanPipeline.parse({
      ...base,
      network: 'grpc',
      'grpc-opts': { 'grpc-service-name': 'TrojanService' },
    })

    expect(result.transport).toEqual({ type: 'grpc', service_name: 'TrojanService' })
  })

  it('leaves transport unset for plain TCP', () => {
    expect(TrojanPipeline.parse(base).transport).toBeUndefined()
  })
})

describe('packet encoding', () => {
  it.each(['packetaddr', 'xudp'] as const)('vmess maps packet-encoding %s', encoding => {
    const result = VmessPipeline.parse({
      type: 'vmess',
      name: 'v',
      server: '1.2.3.4',
      port: 443,
      uuid: 'u',
      alterId: 0,
      cipher: 'auto',
      'packet-encoding': encoding,
    })

    expect(result.packet_encoding).toBe(encoding)
  })

  it('vless maps packet-encoding', () => {
    const result = VLESSPipeline.parse({
      type: 'vless',
      name: 'v',
      server: '1.2.3.4',
      port: 443,
      uuid: 'u',
      'packet-encoding': 'xudp',
    })

    expect(result.packet_encoding).toBe('xudp')
  })

  it('vmess maps global-padding and authenticated-length', () => {
    const result = VmessPipeline.parse({
      type: 'vmess',
      name: 'v',
      server: '1.2.3.4',
      port: 443,
      uuid: 'u',
      alterId: 0,
      cipher: 'auto',
      'global-padding': true,
      'authenticated-length': true,
    })

    expect(result.global_padding).toBe(true)
    expect(result.authenticated_length).toBe(true)
  })
})
