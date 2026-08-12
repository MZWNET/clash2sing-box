import { doConvertHttp } from '../src/libs/converters/http.ts'

describe('doConvertHttp', () => {
  it('converts basic fields without auth', () => {
    const proxy = {
      name: 'test-http',
      server: '10.0.0.1',
      port: 8080,
      type: 'http' as const,
    }

    const result = doConvertHttp(proxy)

    expect(result.type).toBe('http')
    expect(result.tag).toBe('test-http')
    expect(result.server).toBe('10.0.0.1')
    expect(result.server_port).toBe(8080)
    expect(result.username).toBeUndefined()
    expect(result.password).toBeUndefined()
    expect(result.tls).toBeUndefined()
  })

  it('converts with username and password', () => {
    const proxy = {
      name: 'test',
      server: '10.0.0.1',
      port: 8080,
      type: 'http' as const,
      username: 'admin',
      password: 'secret',
    }

    const result = doConvertHttp(proxy)

    expect(result.username).toBe('admin')
    expect(result.password).toBe('secret')
  })

  it('sets username without password when password is undefined', () => {
    const proxy = {
      name: 'test',
      server: '10.0.0.1',
      port: 8080,
      type: 'http' as const,
      username: 'admin',
    }

    const result = doConvertHttp(proxy)

    expect(result.username).toBe('admin')
    expect(result.password).toBeUndefined()
  })

  it('does not set password when username is undefined', () => {
    const proxy = {
      name: 'test',
      server: '10.0.0.1',
      port: 8080,
      type: 'http' as const,
      password: 'secret',
    }

    const result = doConvertHttp(proxy)

    expect(result.username).toBeUndefined()
    expect(result.password).toBeUndefined()
  })

  it('converts with TLS enabled', () => {
    const proxy = {
      name: 'test',
      server: '10.0.0.1',
      port: 443,
      type: 'http' as const,
      tls: true,
      sni: 'proxy.example.com',
      'skip-cert-verify': true,
    }

    const result = doConvertHttp(proxy)

    expect(result.tls).toEqual({
      enabled: true,
      server_name: 'proxy.example.com',
      insecure: true,
    })
  })

  it('omits tls field when tls is undefined', () => {
    const proxy = {
      name: 'test',
      server: '10.0.0.1',
      port: 8080,
      type: 'http' as const,
    }

    const result = doConvertHttp(proxy)

    expect(result.tls).toBeUndefined()
  })
})
