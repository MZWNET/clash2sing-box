import type { z } from 'zod'
import type { ClashProxyShadowsocks } from '../src/libs/types.ts'
import { doConvertShadowsocks } from '../src/libs/converters/shadowsocks.ts'

type SSProxy = z.infer<typeof ClashProxyShadowsocks>

function makeSSProxy(overrides: Partial<SSProxy> = {}): SSProxy {
  return {
    name: 'test-ss',
    server: '1.2.3.4',
    port: 8388,
    type: 'ss',
    cipher: 'aes-256-gcm',
    password: 'test-pass',
    ...overrides,
  }
}

describe('doConvertShadowsocks', () => {
  it('converts basic fields: cipher → method, password, name → tag', () => {
    const result = doConvertShadowsocks(makeSSProxy())
    expect(result).toEqual({
      type: 'shadowsocks',
      tag: 'test-ss',
      server: '1.2.3.4',
      server_port: 8388,
      method: 'aes-256-gcm',
      password: 'test-pass',
    })
  })

  it('renames plugin "obfs" to "obfs-local"', () => {
    const result = doConvertShadowsocks(
      makeSSProxy({
        'plugin': 'obfs',
        'plugin-opts': { mode: 'http' },
      }),
    )
    expect(result.plugin).toBe('obfs-local')
  })

  it('keeps plugin "v2ray-plugin" as-is', () => {
    const result = doConvertShadowsocks(
      makeSSProxy({
        'plugin': 'v2ray-plugin',
        'plugin-opts': { mode: 'websocket' },
      }),
    )
    expect(result.plugin).toBe('v2ray-plugin')
  })

  it('plugin opts: mode only → "mode=http"', () => {
    const result = doConvertShadowsocks(
      makeSSProxy({
        'plugin': 'obfs',
        'plugin-opts': { mode: 'http' },
      }),
    )
    expect(result.plugin_opts).toBe('mode=http')
  })

  it('plugin opts: mode + host → "mode=http;host=example.com"', () => {
    const result = doConvertShadowsocks(
      makeSSProxy({
        'plugin': 'obfs',
        'plugin-opts': { mode: 'http', host: 'example.com' },
      }),
    )
    expect(result.plugin_opts).toBe('mode=http;host=example.com')
  })

  it('plugin opts: v2ray-plugin with tls=true → adds ";tls"', () => {
    const result = doConvertShadowsocks(
      makeSSProxy({
        'plugin': 'v2ray-plugin',
        'plugin-opts': { mode: 'websocket', tls: true },
      }),
    )
    expect(result.plugin_opts).toBe('mode=websocket;tls')
  })

  it('plugin opts: v2ray-plugin with path → adds ";path=/ws"', () => {
    const result = doConvertShadowsocks(
      makeSSProxy({
        'plugin': 'v2ray-plugin',
        'plugin-opts': { mode: 'websocket', path: '/ws' },
      }),
    )
    expect(result.plugin_opts).toBe('mode=websocket;path=/ws')
  })

  it('plugin opts: v2ray-plugin with mux → adds ";mux=true"', () => {
    const result = doConvertShadowsocks(
      makeSSProxy({
        'plugin': 'v2ray-plugin',
        'plugin-opts': { mode: 'websocket', mux: true },
      }),
    )
    expect(result.plugin_opts).toBe('mode=websocket;mux=true')
  })

  it('udp-over-tcp: true → { enabled: true }', () => {
    const result = doConvertShadowsocks(
      makeSSProxy({ 'udp-over-tcp': true }),
    )
    expect(result.udp_over_tcp).toEqual({ enabled: true })
  })

  it('udp-over-tcp with version → { enabled: true, version: 2 }', () => {
    const result = doConvertShadowsocks(
      makeSSProxy({
        'udp-over-tcp': true,
        'udp-over-tcp-version': 2,
      }),
    )
    expect(result.udp_over_tcp).toEqual({ enabled: true, version: 2 })
  })
})
