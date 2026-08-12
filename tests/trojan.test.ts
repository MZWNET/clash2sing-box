import type { ClashProxyTrojan } from '../src/libs/types.ts'
import type { z } from 'zod'
import { doConvertTrojan } from '../src/libs/converters/trojan.ts'

type TrojanProxy = z.infer<typeof ClashProxyTrojan>

function makeTrojanProxy(overrides: Partial<TrojanProxy> = {}): TrojanProxy {
  return {
    name: 'test-trojan',
    server: '1.2.3.4',
    port: 443,
    type: 'trojan',
    password: 'trojan-pass',
    ...overrides,
  }
}

describe('doConvertTrojan', () => {
  it('converts basic fields: password, name → tag', () => {
    const result = doConvertTrojan(makeTrojanProxy())
    expect(result).toEqual({
      type: 'trojan',
      tag: 'test-trojan',
      server: '1.2.3.4',
      server_port: 443,
      password: 'trojan-pass',
      tls: { enabled: true },
    })
  })

  it('converts TLS via doConvertTLSTransport (enabled by default)', () => {
    const result = doConvertTrojan(makeTrojanProxy())
    expect(result.tls).toEqual({ enabled: true })
  })

  it('maps sni to tls server_name', () => {
    const result = doConvertTrojan(makeTrojanProxy({ sni: 'trojan.example.com' }))
    expect(result.tls).toEqual({
      enabled: true,
      server_name: 'trojan.example.com',
    })
  })

  it('handles all TLS options: sni, alpn, skip-cert-verify', () => {
    const result = doConvertTrojan(
      makeTrojanProxy({
        sni: 'full.example.com',
        alpn: ['h2', 'http/1.1'],
        'skip-cert-verify': true,
      }),
    )
    expect(result.tls).toEqual({
      enabled: true,
      server_name: 'full.example.com',
      alpn: ['h2', 'http/1.1'],
      insecure: true,
    })
  })
})
