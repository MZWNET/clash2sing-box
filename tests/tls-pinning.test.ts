import type { SingboxConfig, SingboxOutboundCommonTls } from '../src/schemas/singbox.ts'
import { convert } from '../src/convert.ts'
import { certificateSha256 } from '../src/converters/shared.ts'

/** The same digest in the three shapes mihomo accepts, and what sing-box wants back. */
const HEX = '7EA15B96CE1E4D4C76CBF48EE86EA7CCA09653BE4E982C054C56DA347B0B9738'
const COLONS = '7E:A1:5B:96:CE:1E:4D:4C:76:CB:F4:8E:E8:6E:A7:CC:A0:96:53:BE:4E:98:2C:05:4C:56:DA:34:7B:0B:97:38'
const BASE64 = 'fqFbls4eTUx2y/SO6G6nzKCWU75OmCwFTFbaNHsLlzg='

function tlsOf(config: SingboxConfig, tag: string): SingboxOutboundCommonTls | undefined {
  const outbound = config.outbounds!.find(entry => entry.tag === tag)
  return outbound !== undefined && 'tls' in outbound ? outbound.tls : undefined
}

function pinned(fingerprint: string): { tls: SingboxOutboundCommonTls | undefined; warnings: string[] } {
  const { config, warnings } = convert({
    proxies: [
      { name: 'home-01', type: 'trojan', server: '1.2.3.4', port: 443, password: 'pw', sni: 'e.com', fingerprint },
    ],
  })
  return { tls: tlsOf(config, 'home-01'), warnings }
}

// Both sides hash the whole DER certificate; only the encoding differs.
describe('certificateSha256', () => {
  it.each([
    ['plain hex', HEX],
    ['colon-separated hex', COLONS],
    ['lower case', HEX.toLowerCase()],
    ['surrounded by whitespace', `  ${HEX}  `],
  ])('re-encodes %s as base64', (_what, fingerprint) => {
    expect(certificateSha256(fingerprint)).toEqual([BASE64])
  })

  it.each([
    ['undefined', undefined],
    ['a browser name left over from the uTLS days', 'chrome'],
    ['a truncated digest', '7EA15B96'],
    ['an over-long digest', `${HEX}AA`],
    ['a non-hex digit', HEX.replace('7E', 'ZZ')],
    ['base64 rather than hex', BASE64],
  ])('rejects %s', (_what, fingerprint) => {
    expect(certificateSha256(fingerprint)).toBeUndefined()
  })
})

describe('fingerprint pinning end to end', () => {
  it('emits certificate_sha256 without a warning', () => {
    const { tls, warnings } = pinned(COLONS)

    expect(tls).toEqual({ enabled: true, server_name: 'e.com', certificate_sha256: [BASE64] })
    expect(warnings).toEqual([])
  })

  // `certificate_sha256` conflicts with `certificate`, which nothing emits any more.
  it('never emits certificate alongside the digest', () => {
    expect(pinned(HEX).tls).not.toHaveProperty('certificate')
  })

  it('warns and drops a fingerprint that is not a digest', () => {
    const { tls, warnings } = pinned('chrome')

    expect(tls).toEqual({ enabled: true, server_name: 'e.com' })
    expect(warnings[0]).toContain('Dropped "fingerprint" from proxy "home-01"')
    expect(warnings[0]).toContain('client-fingerprint')
  })

  // sing-box rejects a `tls` block outright on Shadowsocks, SOCKS, SSH and Snell, so a
  // fingerprint on one of those has nowhere to go.
  it('leaves a proxy that carries no tls block alone', () => {
    const { config, warnings } = convert({
      proxies: [{ name: 'ss-01', type: 'ss', server: '1.2.3.4', port: 8388, cipher: 'aes-256-gcm', password: 'pw' }],
    })

    expect(tlsOf(config, 'ss-01')).toBeUndefined()
    expect(warnings).toEqual([])
  })
})
