import { Hysteria2Pipeline } from '../src/converters/hysteria2.ts'

describe('hysteria2 pipeline', () => {
  it('converts basic required fields', () => {
    const proxy = {
      name: 'test-hy2',
      server: '1.2.3.4',
      port: 443,
      type: 'hysteria2' as const,
      password: 'my-password',
    }

    const result = Hysteria2Pipeline.parse(proxy)

    expect(result.type).toBe('hysteria2')
    expect(result.tag).toBe('test-hy2')
    expect(result.server).toBe('1.2.3.4')
    expect(result.server_port).toBe(443)
    expect(result.password).toBe('my-password')
    expect(result.tls).toBeDefined()
    expect(result.tls?.enabled).toBe(true)
  })

  it('parses speed: up="100 Mbps" → up_mbps=100, down="50 Mbps" → down_mbps=50', () => {
    const proxy = {
      name: 'test',
      server: '1.2.3.4',
      port: 443,
      type: 'hysteria2' as const,
      password: 'pass',
      up: '100 Mbps',
      down: '50 Mbps',
    }

    const result = Hysteria2Pipeline.parse(proxy)

    expect(result.up_mbps).toBe(100)
    expect(result.down_mbps).toBe(50)
  })

  it('returns undefined up_mbps/down_mbps when up/down are undefined', () => {
    const proxy = {
      name: 'test',
      server: '1.2.3.4',
      port: 443,
      type: 'hysteria2' as const,
      password: 'pass',
    }

    const result = Hysteria2Pipeline.parse(proxy)

    expect(result.up_mbps).toBeUndefined()
    expect(result.down_mbps).toBeUndefined()
  })

  it('converts ports: comma-separated "443,8443" → ["443", "8443"]', () => {
    const proxy = {
      name: 'test',
      server: '1.2.3.4',
      port: 443,
      type: 'hysteria2' as const,
      password: 'pass',
      ports: '443,8443',
    }

    const result = Hysteria2Pipeline.parse(proxy)

    expect(result.server_ports).toEqual(['443', '8443'])
  })

  it('converts ports: dash range "443-8443" → ["443:8443"]', () => {
    const proxy = {
      name: 'test',
      server: '1.2.3.4',
      port: 443,
      type: 'hysteria2' as const,
      password: 'pass',
      ports: '443-8443',
    }

    const result = Hysteria2Pipeline.parse(proxy)

    expect(result.server_ports).toEqual(['443:8443'])
  })

  it('converts ports: slash-separated "443/8443" → ["443", "8443"]', () => {
    const proxy = {
      name: 'test',
      server: '1.2.3.4',
      port: 443,
      type: 'hysteria2' as const,
      password: 'pass',
      ports: '443/8443',
    }

    const result = Hysteria2Pipeline.parse(proxy)

    expect(result.server_ports).toEqual(['443', '8443'])
  })

  it('converts TLS with reality-opts', () => {
    const proxy = {
      name: 'test',
      server: '1.2.3.4',
      port: 443,
      type: 'hysteria2' as const,
      password: 'pass',
      sni: 'reality.example.com',
      'reality-opts': {
        'public-key': 'abc123',
        'short-id': 'def456',
      },
    }

    const result = Hysteria2Pipeline.parse(proxy)

    expect(result.tls?.reality).toEqual({
      enabled: true,
      public_key: 'abc123',
      short_id: 'def456',
    })
  })

  it('converts TLS with ech-opts', () => {
    const proxy = {
      name: 'test',
      server: '1.2.3.4',
      port: 443,
      type: 'hysteria2' as const,
      password: 'pass',
      'ech-opts': {
        enable: true,
        config: 'ech-config-string',
      },
    }

    const result = Hysteria2Pipeline.parse(proxy)

    expect(result.tls?.ech).toEqual({
      enabled: true,
      config: 'ech-config-string',
    })
  })

  it('converts TLS with fingerprint', () => {
    const proxy = {
      name: 'test',
      server: '1.2.3.4',
      port: 443,
      type: 'hysteria2' as const,
      password: 'pass',
      fingerprint: 'chrome',
    }

    const result = Hysteria2Pipeline.parse(proxy)

    expect(result.tls?.utls).toEqual({
      enabled: true,
      fingerprint: 'chrome',
    })
  })

  it('converts TLS with client-fingerprint', () => {
    const proxy = {
      name: 'test',
      server: '1.2.3.4',
      port: 443,
      type: 'hysteria2' as const,
      password: 'pass',
      'client-fingerprint': 'firefox',
    }

    const result = Hysteria2Pipeline.parse(proxy)

    expect(result.tls?.utls).toEqual({
      enabled: true,
      fingerprint: 'firefox',
    })
  })

  it('converts obfs with obfs-password', () => {
    const proxy = {
      name: 'test',
      server: '1.2.3.4',
      port: 443,
      type: 'hysteria2' as const,
      password: 'pass',
      obfs: 'salamander',
      'obfs-password': 'obfs-secret',
    }

    const result = Hysteria2Pipeline.parse(proxy)

    expect(result.obfs).toEqual({
      type: 'salamander',
      password: 'obfs-secret',
    })
  })

  it('converts tcp_fast_open, tcp_multi_path, bind_interface, routing_mark', () => {
    const proxy = {
      name: 'test',
      server: '1.2.3.4',
      port: 443,
      type: 'hysteria2' as const,
      password: 'pass',
      tfo: true,
      mptcp: true,
      'interface-name': 'eth0',
      'routing-mark': 255,
    }

    const result = Hysteria2Pipeline.parse(proxy)

    expect(result.tcp_fast_open).toBe(true)
    expect(result.tcp_multi_path).toBe(true)
    expect(result.bind_interface).toBe('eth0')
    expect(result.routing_mark).toBe(255)
  })
})
