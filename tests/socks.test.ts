import type { ClashProxySocks5 } from '../src/libs/types.ts'
import type { z } from 'zod'
import { doConvertSocks5ToSocks } from '../src/libs/converters/socks.ts'

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

describe('doConvertSocks5ToSocks', () => {
  it('converts basic fields without auth', () => {
    const result = doConvertSocks5ToSocks(makeSocksProxy())
    expect(result).toEqual({
      type: 'socks',
      tag: 'test-socks',
      server: '1.2.3.4',
      server_port: 1080,
    })
  })

  it('includes username when provided', () => {
    const result = doConvertSocks5ToSocks(makeSocksProxy({ username: 'user1' }))
    expect(result.username).toBe('user1')
  })

  it('includes username and password when both provided', () => {
    const result = doConvertSocks5ToSocks(makeSocksProxy({ username: 'user1', password: 'pass1' }))
    expect(result.username).toBe('user1')
    expect(result.password).toBe('pass1')
  })

  it('does not include password without username', () => {
    const result = doConvertSocks5ToSocks(makeSocksProxy({ password: 'pass1' }))
    expect(result.username).toBeUndefined()
    expect(result.password).toBeUndefined()
  })

  it('throws error for tls=true', () => {
    expect(() => doConvertSocks5ToSocks(makeSocksProxy({ tls: true }))).toThrow('Unsupported layer tls')
  })
})
