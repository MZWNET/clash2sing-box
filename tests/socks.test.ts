import type { ClashProxySocks5 } from '../src/index.ts'
import type { z } from 'zod'
import { Socks5Pipeline } from '../src/converters/socks.ts'

type SocksProxy = z.infer<typeof ClashProxySocks5>

function makeSocksProxy(overrides: Partial<SocksProxy> = {}): SocksProxy {
  return {
    name: 'test-socks',
    server: '1.2.3.4',
    port: 1080,
    type: 'socks5',
    ...overrides,
  }
}

describe('socks5 pipeline', () => {
  it('converts basic fields without auth', () => {
    const result = Socks5Pipeline.parse(makeSocksProxy())
    expect(result).toEqual({
      type: 'socks',
      tag: 'test-socks',
      server: '1.2.3.4',
      server_port: 1080,
    })
  })

  it('includes username when provided', () => {
    const result = Socks5Pipeline.parse(makeSocksProxy({ username: 'user1' }))
    expect(result.username).toBe('user1')
  })

  it('includes username and password when both provided', () => {
    const result = Socks5Pipeline.parse(makeSocksProxy({ username: 'user1', password: 'pass1' }))
    expect(result.username).toBe('user1')
    expect(result.password).toBe('pass1')
  })

  it('does not include password without username', () => {
    const result = Socks5Pipeline.parse(makeSocksProxy({ password: 'pass1' }))
    expect(result.username).toBeUndefined()
    expect(result.password).toBeUndefined()
  })

  it('rejects tls=true without throwing', () => {
    const result = Socks5Pipeline.safeParse(makeSocksProxy({ tls: true }))

    expect(result.success).toBe(false)
    expect(result.error?.issues[0]?.message).toBe('sing-box does not support a TLS layer on SOCKS')
  })
})
