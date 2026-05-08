import type { z } from 'zod'
import type { ClashProxyTUIC } from '../src/libs/types.ts'
import { doConvertTUIC } from '../src/libs/converters/tuic.ts'

type TUICProxy = z.infer<typeof ClashProxyTUIC>

function makeTUICProxy(overrides: Partial<TUICProxy> = {}): TUICProxy {
  return {
    name: 'test-tuic',
    server: '1.2.3.4',
    port: 443,
    type: 'tuic',
    uuid: 'b831381d-678a-4521-a398-a97113b03679',
    ...overrides,
  }
}

describe('doConvertTUIC', () => {
  it('converts basic fields: name → tag, server, port, uuid', () => {
    const result = doConvertTUIC(makeTUICProxy())
    expect(result.type).toBe('tuic')
    expect(result.tag).toBe('test-tuic')
    expect(result.server).toBe('1.2.3.4')
    expect(result.server_port).toBe(443)
    expect(result.uuid).toBe('b831381d-678a-4521-a398-a97113b03679')
  })

  it('always includes tls with enabled: true', () => {
    const result = doConvertTUIC(makeTUICProxy())
    expect(result.tls).toEqual({ enabled: true })
  })

  it('converts TLS fields (sni, alpn, skip-cert-verify)', () => {
    const result = doConvertTUIC(makeTUICProxy({
      'sni': 'tuic.example.com',
      'alpn': ['h3'],
      'skip-cert-verify': true,
    }))
    expect(result.tls).toEqual({
      enabled: true,
      server_name: 'tuic.example.com',
      alpn: ['h3'],
      insecure: true,
    })
  })

  it('maps optional password field', () => {
    const result = doConvertTUIC(makeTUICProxy({ password: 'my-secret' }))
    expect(result.password).toBe('my-secret')
  })

  it('omits password when not provided', () => {
    const result = doConvertTUIC(makeTUICProxy())
    expect(result.password).toBeUndefined()
  })

  it('converts heartbeat-interval from milliseconds to seconds string', () => {
    const result = doConvertTUIC(makeTUICProxy({ 'heartbeat-interval': 30000 }))
    expect(result.heartbeat).toBe('30s')
  })

  it('converts heartbeat-interval with non-round values', () => {
    const result = doConvertTUIC(makeTUICProxy({ 'heartbeat-interval': 5000 }))
    expect(result.heartbeat).toBe('5s')
  })

  it('maps reduce-rtt: true to zero_rtt_handshake: true', () => {
    const result = doConvertTUIC(makeTUICProxy({ 'reduce-rtt': true }))
    expect(result.zero_rtt_handshake).toBe(true)
  })

  it('does not set zero_rtt_handshake when reduce-rtt is false', () => {
    const result = doConvertTUIC(makeTUICProxy({ 'reduce-rtt': false }))
    expect(result.zero_rtt_handshake).toBeUndefined()
  })

  it('maps udp-relay-mode to udp_relay_mode', () => {
    const result = doConvertTUIC(makeTUICProxy({ 'udp-relay-mode': 'quic' }))
    expect(result.udp_relay_mode).toBe('quic')
  })

  it('maps congestion-controller to congestion_control', () => {
    const result = doConvertTUIC(makeTUICProxy({ 'congestion-controller': 'bbr' }))
    expect(result.congestion_control).toBe('bbr')
  })

  it('maps udp-over-stream: true to udp_over_stream: true', () => {
    const result = doConvertTUIC(makeTUICProxy({ 'udp-over-stream': true }))
    expect(result.udp_over_stream).toBe(true)
  })

  it('does not set udp_over_stream when udp-over-stream is false', () => {
    const result = doConvertTUIC(makeTUICProxy({ 'udp-over-stream': false }))
    expect(result.udp_over_stream).toBeUndefined()
  })

  it('converts all optional fields together', () => {
    const result = doConvertTUIC(makeTUICProxy({
      'password': 'pass123',
      'heartbeat-interval': 10000,
      'reduce-rtt': true,
      'udp-relay-mode': 'native',
      'congestion-controller': 'cubic',
      'udp-over-stream': true,
      'sni': 'full.example.com',
      'alpn': ['h3', 'h3-29'],
    }))
    expect(result).toEqual({
      type: 'tuic',
      tag: 'test-tuic',
      server: '1.2.3.4',
      server_port: 443,
      uuid: 'b831381d-678a-4521-a398-a97113b03679',
      tls: {
        enabled: true,
        server_name: 'full.example.com',
        alpn: ['h3', 'h3-29'],
      },
      password: 'pass123',
      heartbeat: '10s',
      zero_rtt_handshake: true,
      udp_relay_mode: 'native',
      congestion_control: 'cubic',
      udp_over_stream: true,
    })
  })
})
