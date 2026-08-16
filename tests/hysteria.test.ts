import { HysteriaPipeline } from '../src/converters/hysteria.ts'

describe('hysteria pipeline', () => {
  it('converts basic fields with protocol udp', () => {
    const proxy = {
      name: 'test-hy',
      server: '1.2.3.4',
      port: 443,
      type: 'hysteria' as const,
      protocol: 'udp' as const,
      up: '100 Mbps',
      down: '200 Mbps',
    }

    const result = HysteriaPipeline.parse(proxy)

    expect(result.type).toBe('hysteria')
    expect(result.tag).toBe('test-hy')
    expect(result.server).toBe('1.2.3.4')
    expect(result.server_port).toBe(443)
    expect(result.up).toBe('100 Mbps')
    expect(result.down).toBe('200 Mbps')
    expect(result.tls).toEqual({ enabled: true })
  })

  it.each(['faketcp', 'wechat-video'] as const)('rejects unsupported protocol %s without throwing', protocol => {
    const proxy = {
      name: 'test',
      server: '1.2.3.4',
      port: 443,
      type: 'hysteria' as const,
      protocol,
      up: '100',
      down: '200',
    }

    const result = HysteriaPipeline.safeParse(proxy)

    expect(result.success).toBe(false)
    expect(result.error?.issues[0]?.message).toBe(`sing-box does not support the Hysteria protocol "${protocol}"`)
  })

  it('converts optional obfs field', () => {
    const proxy = {
      name: 'test',
      server: '1.2.3.4',
      port: 443,
      type: 'hysteria' as const,
      protocol: 'udp' as const,
      up: '100',
      down: '200',
      obfs: 'obfs-password',
    }

    const result = HysteriaPipeline.parse(proxy)

    expect(result.obfs).toBe('obfs-password')
  })

  it('converts optional auth-str to auth_str', () => {
    const proxy = {
      name: 'test',
      server: '1.2.3.4',
      port: 443,
      type: 'hysteria' as const,
      protocol: 'udp' as const,
      up: '100',
      down: '200',
      'auth-str': 'my-auth-token',
    }

    const result = HysteriaPipeline.parse(proxy)

    expect(result.auth_str).toBe('my-auth-token')
  })

  it('omits obfs and auth_str when not provided', () => {
    const proxy = {
      name: 'test',
      server: '1.2.3.4',
      port: 443,
      type: 'hysteria' as const,
      protocol: 'udp' as const,
      up: '100',
      down: '200',
    }

    const result = HysteriaPipeline.parse(proxy)

    expect(result.obfs).toBeUndefined()
    expect(result.auth_str).toBeUndefined()
  })
})
