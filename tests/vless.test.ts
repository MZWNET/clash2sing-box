import type { ClashProxyVLESS as ClashProxyVLESSType } from '../src/index.ts'
import type { z } from 'zod'
import { VLESSPipeline } from '../src/converters/vless.ts'
import { ClashProxyVLESS } from '../src/index.ts'

type VLESSProxy = z.infer<typeof ClashProxyVLESSType>

function makeVLESSProxy(overrides: Partial<VLESSProxy> = {}): VLESSProxy {
  return {
    name: 'test-vless',
    server: '1.2.3.4',
    port: 443,
    type: 'vless',
    uuid: 'b831381d-678a-4521-a398-a97113b03679',
    ...overrides,
  }
}

describe('vless pipeline', () => {
  it('converts basic fields: name → tag, server, port, uuid', () => {
    const result = VLESSPipeline.parse(makeVLESSProxy())
    expect(result.type).toBe('vless')
    expect(result.tag).toBe('test-vless')
    expect(result.server).toBe('1.2.3.4')
    expect(result.server_port).toBe(443)
    expect(result.uuid).toBe('b831381d-678a-4521-a398-a97113b03679')
  })

  it('converts TLS when tls: true is set', () => {
    const result = VLESSPipeline.parse(
      makeVLESSProxy({
        tls: true,
        sni: 'vless.example.com',
        alpn: ['h2', 'http/1.1'],
      }),
    )
    expect(result.tls).toEqual({
      enabled: true,
      server_name: 'vless.example.com',
      alpn: ['h2', 'http/1.1'],
    })
  })

  it('does not set tls when tls field is undefined', () => {
    const result = VLESSPipeline.parse(makeVLESSProxy())
    expect(result.tls).toBeUndefined()
  })

  it('converts ws-opts to transport with type: ws', () => {
    const result = VLESSPipeline.parse(
      makeVLESSProxy({
        'ws-opts': {
          path: '/vless-ws',
          headers: { Host: 'ws.example.com' },
        },
      }),
    )
    expect(result.transport).toEqual({
      type: 'ws',
      path: '/vless-ws',
      headers: { Host: 'ws.example.com' },
    })
  })

  it('converts h2-opts to transport with type: http', () => {
    const result = VLESSPipeline.parse(
      makeVLESSProxy({
        'h2-opts': {
          host: ['h2.example.com'],
          path: '/vless-h2',
        },
      }),
    )
    expect(result.transport).toEqual({
      type: 'http',
      host: ['h2.example.com'],
      path: '/vless-h2',
    })
  })

  it('converts grpc-opts to transport with type: grpc', () => {
    const result = VLESSPipeline.parse(
      makeVLESSProxy({
        'grpc-opts': {
          'grpc-service-name': 'vless.grpc.service',
        },
      }),
    )
    expect(result.transport).toEqual({
      type: 'grpc',
      service_name: 'vless.grpc.service',
    })
  })

  it('does not set transport when no opts present', () => {
    const result = VLESSPipeline.parse(makeVLESSProxy())
    expect(result.transport).toBeUndefined()
  })

  it('maps optional flow field', () => {
    const result = VLESSPipeline.parse(
      makeVLESSProxy({
        flow: 'xtls-rprx-vision',
      }),
    )
    expect(result.flow).toBe('xtls-rprx-vision')
  })

  it('converts with TLS and transport together', () => {
    const result = VLESSPipeline.parse(
      makeVLESSProxy({
        tls: true,
        sni: 'full.example.com',
        'skip-cert-verify': true,
        'ws-opts': {
          path: '/ws',
          headers: { Host: 'full.example.com' },
        },
      }),
    )
    expect(result.tls).toEqual({
      enabled: true,
      server_name: 'full.example.com',
      insecure: true,
    })
    expect(result.transport).toEqual({
      type: 'ws',
      path: '/ws',
      headers: { Host: 'full.example.com' },
    })
  })
})

describe('clashProxyVLESS schema', () => {
  it('parses vless with security tls and ws-opts', () => {
    const result = ClashProxyVLESS.safeParse({
      type: 'vless',
      name: 'vless-ws-tls',
      server: '10.0.0.1',
      port: 443,
      uuid: '11111111-2222-3333-4444-555555555555',
      security: 'tls',
      tls: true,
      servername: 'ws.example.com',
      network: 'ws',
      'client-fingerprint': 'chrome',
      'ws-opts': {
        path: '/ws',
        headers: { Host: 'ws.example.com' },
      },
    })
    expect(result.success).toBe(true)
  })

  it('parses vless with security reality and reality-opts', () => {
    const result = ClashProxyVLESS.safeParse({
      type: 'vless',
      name: 'vless-reality',
      server: '10.0.0.2',
      port: 443,
      uuid: 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee',
      security: 'reality',
      tls: true,
      servername: 'target.example.com',
      network: 'tcp',
      flow: 'xtls-rprx-vision',
      'client-fingerprint': 'qq',
      'reality-opts': {
        'public-key': 'abc123',
        'short-id': 'abcd',
      },
    })
    expect(result.success).toBe(true)
  })

  it('parses vless with network tcp and optional fields', () => {
    const result = ClashProxyVLESS.safeParse({
      type: 'vless',
      name: 'vless-tcp',
      server: '10.0.0.3',
      port: 8443,
      uuid: '12345678-1234-1234-1234-123456789abc',
      security: 'tls',
      tls: true,
      network: 'tcp',
      udp: true,
      'skip-cert-verify': true,
      alpn: ['h2', 'http/1.1'],
      encryption: 'none',
      'client-fingerprint': 'chrome',
      tfo: true,
    })
    expect(result.success).toBe(true)
  })

  it('parses vless with ech-opts without failing', () => {
    const result = ClashProxyVLESS.safeParse({
      type: 'vless',
      name: 'vless-ech',
      server: '10.0.0.4',
      port: 443,
      uuid: 'aaaaaaaa-bbbb-cccc-dddd-111111111111',
      tls: true,
      'ech-opts': {
        enable: true,
        config: 'abc',
        'query-server-name': 'example.com',
      },
    })
    expect(result.success).toBe(true)
  })
})

describe('vless pipeline REALITY/ECH', () => {
  it('emits tls.reality from reality-opts', () => {
    const result = VLESSPipeline.parse(
      makeVLESSProxy({
        tls: true,
        sni: 'reality.example.com',
        'reality-opts': { 'public-key': 'pubkey123', 'short-id': 'short456' },
      }),
    )

    expect(result.tls?.reality).toEqual({
      enabled: true,
      public_key: 'pubkey123',
      short_id: 'short456',
    })
    expect(result.tls?.server_name).toBe('reality.example.com')
  })

  it('emits tls even when reality is configured without an explicit tls: true', () => {
    const result = VLESSPipeline.parse(
      makeVLESSProxy({
        security: 'reality',
        'reality-opts': { 'public-key': 'pubkey123' },
      }),
    )

    expect(result.tls?.enabled).toBe(true)
    expect(result.tls?.reality?.public_key).toBe('pubkey123')
  })

  it('emits tls.ech from ech-opts', () => {
    const result = VLESSPipeline.parse(
      makeVLESSProxy({ tls: true, 'ech-opts': { enable: true, config: 'ech-config' } }),
    )

    expect(result.tls?.ech).toEqual({ enabled: true, config: 'ech-config' })
  })

  it('does not emit tls.ech when ech-opts is disabled', () => {
    const result = VLESSPipeline.parse(makeVLESSProxy({ tls: true, 'ech-opts': { enable: false } }))

    expect(result.tls?.ech).toBeUndefined()
  })

  it('emits tls.utls from client-fingerprint', () => {
    const result = VLESSPipeline.parse(makeVLESSProxy({ tls: true, 'client-fingerprint': 'chrome' }))

    expect(result.tls?.utls).toEqual({ enabled: true, fingerprint: 'chrome' })
  })

  it('does not emit a tls block when tls is explicitly false', () => {
    const result = VLESSPipeline.parse(makeVLESSProxy({ tls: false }))

    expect(result.tls).toBeUndefined()
  })
})
