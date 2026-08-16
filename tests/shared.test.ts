import type { ClashProxyBaseTLS, ClashProxyBaseVmessOrVLESS } from '../src/index.ts'
import type { z } from 'zod'
import { convertTLSTransport, convertTransport } from '../src/converters/shared.ts'

type TLSProxy = z.infer<typeof ClashProxyBaseTLS>
type VmessOrVLESSProxy = z.infer<typeof ClashProxyBaseVmessOrVLESS>

function makeTLSProxy(overrides: Partial<TLSProxy> = {}): TLSProxy {
  return {
    name: 'test',
    server: 'example.com',
    port: 443,
    ...overrides,
  }
}

function makeVmessOrVLESSProxy(overrides: Partial<VmessOrVLESSProxy> = {}): VmessOrVLESSProxy {
  return {
    name: 'test',
    server: 'example.com',
    port: 443,
    uuid: 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee',
    ...overrides,
  }
}

describe('convertTLSTransport', () => {
  it('returns { enabled: true } with minimal input', () => {
    const result = convertTLSTransport(makeTLSProxy())
    expect(result).toEqual({ enabled: true })
  })

  it('maps alpn array correctly', () => {
    const result = convertTLSTransport(makeTLSProxy({ alpn: ['h2', 'http/1.1'] }))
    expect(result).toEqual({ enabled: true, alpn: ['h2', 'http/1.1'] })
  })

  it('maps servername to server_name', () => {
    const result = convertTLSTransport(makeTLSProxy({ servername: 'custom.example.com' }))
    expect(result).toEqual({ enabled: true, server_name: 'custom.example.com' })
  })

  it('maps sni to server_name', () => {
    const result = convertTLSTransport(makeTLSProxy({ sni: 'sni.example.com' }))
    expect(result).toEqual({ enabled: true, server_name: 'sni.example.com' })
  })

  it('sni overrides servername when both present', () => {
    const result = convertTLSTransport(
      makeTLSProxy({
        servername: 'servername.example.com',
        sni: 'sni.example.com',
      }),
    )
    expect(result).toEqual({ enabled: true, server_name: 'sni.example.com' })
  })

  it('maps skip-cert-verify: true to insecure: true', () => {
    const result = convertTLSTransport(makeTLSProxy({ 'skip-cert-verify': true }))
    expect(result).toEqual({ enabled: true, insecure: true })
  })

  it('does not set insecure when skip-cert-verify is false', () => {
    const result = convertTLSTransport(makeTLSProxy({ 'skip-cert-verify': false }))
    expect(result).toEqual({ enabled: true })
    expect(result.insecure).toBeUndefined()
  })

  it('maps x-clash2singbox-certificate to certificate array', () => {
    const certs = ['-----BEGIN CERTIFICATE-----\nabc\n-----END CERTIFICATE-----']
    const result = convertTLSTransport(makeTLSProxy({ 'x-clash2singbox-certificate': certs }))
    expect(result).toEqual({ enabled: true, certificate: certs })
  })

  it('maps x-clash2singbox-certificate-public-key-sha256 correctly', () => {
    const sha256 = 'sha256:abcdef1234567890'
    const result = convertTLSTransport(
      makeTLSProxy({
        'x-clash2singbox-certificate-public-key-sha256': sha256,
      }),
    )
    expect(result).toEqual({
      enabled: true,
      certificate_public_key_sha256: sha256,
    })
  })

  it('handles all fields together (full proxy)', () => {
    const certs = ['cert1', 'cert2']
    const result = convertTLSTransport(
      makeTLSProxy({
        alpn: ['h2'],
        sni: 'full.example.com',
        'skip-cert-verify': true,
        'x-clash2singbox-certificate': certs,
        'x-clash2singbox-certificate-public-key-sha256': 'sha256:full',
      }),
    )
    expect(result).toEqual({
      enabled: true,
      alpn: ['h2'],
      server_name: 'full.example.com',
      insecure: true,
      certificate: certs,
      certificate_public_key_sha256: 'sha256:full',
    })
  })
})

describe('convertTransport', () => {
  it('returns undefined when no transport options present', () => {
    const result = convertTransport(makeVmessOrVLESSProxy())
    expect(result).toBeUndefined()
  })

  it('converts http-opts to { type: "http" } with path, method, headers', () => {
    const result = convertTransport(
      makeVmessOrVLESSProxy({
        'http-opts': {
          path: ['/path1', '/path2'],
          method: 'PUT',
          headers: {
            'X-Custom': ['value1'],
            Host: ['host.example.com'],
          },
        },
      }),
    )
    expect(result).toEqual({
      type: 'http',
      path: '/path1',
      method: 'PUT',
      headers: {
        'X-Custom': 'value1',
        Host: 'host.example.com',
      },
    })
  })

  it('converts http-opts with missing optional fields', () => {
    const result = convertTransport(
      makeVmessOrVLESSProxy({
        'http-opts': {},
      }),
    )
    expect(result).toEqual({ type: 'http' })
  })

  it('converts h2-opts to { type: "http" } with host and path', () => {
    const result = convertTransport(
      makeVmessOrVLESSProxy({
        'h2-opts': {
          host: ['h2.example.com'],
          path: '/h2path',
        },
      }),
    )
    expect(result).toEqual({
      type: 'http',
      host: ['h2.example.com'],
      path: '/h2path',
    })
  })

  it('converts h2-opts with missing optional fields', () => {
    const result = convertTransport(
      makeVmessOrVLESSProxy({
        'h2-opts': {},
      }),
    )
    expect(result).toEqual({ type: 'http' })
  })

  it('converts ws-opts to { type: "ws" } with path, headers, max_early_data, early_data_header_name', () => {
    const result = convertTransport(
      makeVmessOrVLESSProxy({
        'ws-opts': {
          path: '/wspath',
          headers: { Host: 'ws.example.com' },
          'max-early-data': 2048,
          'early-data-header-name': 'Sec-WebSocket-Protocol',
        },
      }),
    )
    expect(result).toEqual({
      type: 'ws',
      path: '/wspath',
      headers: { Host: 'ws.example.com' },
      max_early_data: 2048,
      early_data_header_name: 'Sec-WebSocket-Protocol',
    })
  })

  it('converts ws-opts with missing optional fields', () => {
    const result = convertTransport(
      makeVmessOrVLESSProxy({
        'ws-opts': {},
      }),
    )
    expect(result).toEqual({ type: 'ws' })
  })

  it('converts ws-opts with v2ray-http-upgrade: true to { type: "httpupgrade" }', () => {
    const result = convertTransport(
      makeVmessOrVLESSProxy({
        'ws-opts': {
          path: '/upgrade',
          headers: { Host: 'upgrade.example.com' },
          'v2ray-http-upgrade': true,
        },
      }),
    )
    expect(result).toEqual({
      type: 'httpupgrade',
      path: '/upgrade',
      headers: { Host: 'upgrade.example.com' },
    })
  })

  it('converts ws-opts httpupgrade with missing optional fields', () => {
    const result = convertTransport(
      makeVmessOrVLESSProxy({
        'ws-opts': {
          'v2ray-http-upgrade': true,
        },
      }),
    )
    expect(result).toEqual({ type: 'httpupgrade' })
  })

  it('converts grpc-opts to { type: "grpc" } with service_name', () => {
    const result = convertTransport(
      makeVmessOrVLESSProxy({
        'grpc-opts': {
          'grpc-service-name': 'my.grpc.service',
        },
      }),
    )
    expect(result).toEqual({
      type: 'grpc',
      service_name: 'my.grpc.service',
    })
  })

  it('converts grpc-opts with missing optional service_name', () => {
    const result = convertTransport(
      makeVmessOrVLESSProxy({
        'grpc-opts': {},
      }),
    )
    expect(result).toEqual({ type: 'grpc' })
  })
})
