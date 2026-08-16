import type { ClashProxyVmess } from '../src/index.ts'
import type { z } from 'zod'
import { VmessPipeline } from '../src/converters/vmess.ts'

type VmessProxy = z.infer<typeof ClashProxyVmess>

function makeVmessProxy(overrides: Partial<VmessProxy> = {}): VmessProxy {
  return {
    name: 'test-vmess',
    server: '1.2.3.4',
    port: 443,
    type: 'vmess',
    uuid: 'b831381d-678a-4521-a398-a97113b03679',
    alterId: 0,
    cipher: 'auto',
    ...overrides,
  }
}

describe('vmess pipeline', () => {
  it('converts basic fields: name → tag, server, port, uuid', () => {
    const result = VmessPipeline.parse(makeVmessProxy())
    expect(result.type).toBe('vmess')
    expect(result.tag).toBe('test-vmess')
    expect(result.server).toBe('1.2.3.4')
    expect(result.server_port).toBe(443)
    expect(result.uuid).toBe('b831381d-678a-4521-a398-a97113b03679')
  })

  it('maps cipher to security and alterId to alter_id', () => {
    const result = VmessPipeline.parse(
      makeVmessProxy({
        cipher: 'aes-128-gcm',
        alterId: 2,
      }),
    )
    expect(result.security).toBe('aes-128-gcm')
    expect(result.alter_id).toBe(2)
  })

  it('converts TLS when tls: true is set', () => {
    const result = VmessPipeline.parse(
      makeVmessProxy({
        tls: true,
        sni: 'vmess.example.com',
        alpn: ['h2'],
      }),
    )
    expect(result.tls).toEqual({
      enabled: true,
      server_name: 'vmess.example.com',
      alpn: ['h2'],
    })
  })

  it('does not set tls when tls field is undefined', () => {
    const result = VmessPipeline.parse(makeVmessProxy())
    expect(result.tls).toBeUndefined()
  })

  it('converts ws-opts to transport with type: ws', () => {
    const result = VmessPipeline.parse(
      makeVmessProxy({
        'ws-opts': {
          path: '/vmess-ws',
          headers: { Host: 'ws.example.com' },
        },
      }),
    )
    expect(result.transport).toEqual({
      type: 'ws',
      path: '/vmess-ws',
      headers: { Host: 'ws.example.com' },
    })
  })

  it('converts grpc-opts to transport with type: grpc', () => {
    const result = VmessPipeline.parse(
      makeVmessProxy({
        'grpc-opts': {
          'grpc-service-name': 'vmess.grpc.service',
        },
      }),
    )
    expect(result.transport).toEqual({
      type: 'grpc',
      service_name: 'vmess.grpc.service',
    })
  })

  it('does not set transport when no opts present', () => {
    const result = VmessPipeline.parse(makeVmessProxy())
    expect(result.transport).toBeUndefined()
  })

  it('converts with TLS and transport together', () => {
    const result = VmessPipeline.parse(
      makeVmessProxy({
        tls: true,
        sni: 'full.example.com',
        'skip-cert-verify': true,
        'grpc-opts': {
          'grpc-service-name': 'my.service',
        },
      }),
    )
    expect(result.tls).toEqual({
      enabled: true,
      server_name: 'full.example.com',
      insecure: true,
    })
    expect(result.transport).toEqual({
      type: 'grpc',
      service_name: 'my.service',
    })
  })
})
