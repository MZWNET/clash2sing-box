import type { Options } from '../src/schemas/options.ts'
import type { SingboxConfig, SingboxOutboundCommonTls } from '../src/schemas/singbox.ts'
import { convert } from '../src/convert.ts'
import { CliOptions } from '../src/schemas/options.ts'

const trojan = { name: 'home-01', type: 'trojan', server: '1.2.3.4', port: 443, password: 'pw', sni: 'e.com' }
const shadowsocks = {
  name: 'home-02',
  type: 'ss',
  server: '1.2.3.4',
  port: 8388,
  cipher: 'aes-256-gcm',
  password: 'pw',
}

const CERTIFICATE = ['-----BEGIN CERTIFICATE-----', 'abc', '-----END CERTIFICATE-----']

function tlsOf(config: SingboxConfig, tag: string): SingboxOutboundCommonTls | undefined {
  const outbound = config.outbounds!.find(entry => entry.tag === tag)
  return outbound !== undefined && 'tls' in outbound ? outbound.tls : undefined
}

function parse(...entries: string[]): Options['outbound'] {
  return CliOptions.parse({ outboundTlsCertificatePublicKeySha256: entries }).options.outbound
}

describe('certificate pinning', () => {
  it('pins a certificate onto the outbounds whose tag matches', () => {
    const { config, warnings } = convert(
      { proxies: [trojan] },
      {},
      {
        outbound: { tls: { certificate: [{ match: /^home-/, certificate: CERTIFICATE }] } },
      },
    )

    expect(tlsOf(config, 'home-01')?.certificate).toEqual(CERTIFICATE)
    expect(warnings).toEqual([])
  })

  it('leaves an outbound whose tag does not match alone', () => {
    const { config } = convert(
      { proxies: [trojan] },
      {},
      {
        outbound: { tls: { certificate: [{ match: /^away-/, certificate: CERTIFICATE }] } },
      },
    )

    expect(tlsOf(config, 'home-01')?.certificate).toBeUndefined()
  })

  // sing-box rejects a `tls` block outright on Shadowsocks, SOCKS, SSH and Snell.
  it('skips an outbound that carries no tls block', () => {
    const { config, warnings } = convert(
      { proxies: [shadowsocks] },
      {},
      {
        outbound: { tls: { certificate: [{ match: /^home-/, certificate: CERTIFICATE }] } },
      },
    )

    expect(tlsOf(config, 'home-02')).toBeUndefined()
    expect(warnings).toEqual(['No TLS-capable outbound matches "^home-" to pin a certificate onto'])
  })

  it('collects several public keys onto one outbound', () => {
    const { config } = convert(
      { proxies: [trojan] },
      {},
      {
        outbound: {
          tls: {
            certificatePublicKeySha256: [
              { match: /^home-/, hash: 'aGVsbG8=' },
              { match: /01$/, hash: 'd29ybGQ=' },
            ],
          },
        },
      },
    )

    expect(tlsOf(config, 'home-01')?.certificate_public_key_sha256).toEqual(['aGVsbG8=', 'd29ybGQ='])
  })

  it('leaves the config untouched when neither flag is given', () => {
    const { config } = convert({ proxies: [trojan] }, {}, {})

    expect(tlsOf(config, 'home-01')).toEqual({ enabled: true, server_name: 'e.com' })
  })
})

describe('--outbound-tls-certificate-public-key-sha256 parsing', () => {
  // Base64 padding is a trailing `=`, so the split has to be on the first one.
  it('keeps an "=" in the value', () => {
    expect(parse('^hk=aGVsbG8=')!.tls!.certificatePublicKeySha256).toEqual([{ match: /^hk/, hash: 'aGVsbG8=' }])
  })

  it.each([
    ['no separator', '^hk'],
    ['an empty pattern', '=aGVsbG8='],
    ['an empty value', '^hk='],
  ])('rejects %s', (_what, entry) => {
    const parsed = CliOptions.safeParse({ outboundTlsCertificatePublicKeySha256: [entry] })

    expect(parsed.success).toBe(false)
    expect(parsed.error!.issues[0]!.message).toContain('must look like "regex=base64"')
  })

  it('rejects an uncompilable pattern', () => {
    const parsed = CliOptions.safeParse({ outboundTlsCertificatePublicKeySha256: ['[unterminated=aGVsbG8='] })

    expect(parsed.error!.issues[0]!.message).toContain('has an invalid regex')
  })

  it('is undefined when the flag is absent or empty, so convert falls back', () => {
    expect(parse()!.tls!.certificatePublicKeySha256).toBeUndefined()
    expect(CliOptions.parse({}).options.outbound.tls.certificatePublicKeySha256).toBeUndefined()
  })

  // The certificate flag names a file, so the CLI reads it rather than `convert`.
  it('hands the certificate path back for the CLI to read', () => {
    const parsed = CliOptions.parse({ outboundTlsCertificate: ['^hk=./ca.pem'] })

    expect(parsed.files.tlsCertificate).toEqual([{ match: /^hk/, path: './ca.pem' }])
  })
})
