import { mkdtemp, readFile, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import process from 'node:process'
import { classifyInputs, isHttpUrl, main } from '../src/cli.ts'

async function makeTempDir(): Promise<string> {
  return mkdtemp(join(tmpdir(), 'clash2sing-box-'))
}

const CLASH_YAML = `proxies:
  - name: test-ss
    type: ss
    server: 1.2.3.4
    port: 8388
    cipher: aes-256-gcm
    password: testpassword
`

function captureStreams(): { stdout: string[]; stderr: string[] } {
  const stdout: string[] = []
  const stderr: string[] = []
  vi.spyOn(process.stdout, 'write').mockImplementation(chunk => {
    stdout.push(String(chunk))
    return true
  })
  vi.spyOn(process.stderr, 'write').mockImplementation(chunk => {
    stderr.push(String(chunk))
    return true
  })
  return { stdout, stderr }
}

describe('isHttpUrl', () => {
  it.each(['https://example.com/c.yaml', 'http://example.com', 'HTTP://EXAMPLE.COM'])('accepts %s', input => {
    expect(isHttpUrl(input)).toBe(true)
  })

  it.each(['./tests/clash.yaml', '/abs/path.yaml', 'ftp://example.com', 'C:\\win\\path.yaml', 'not a url'])(
    'rejects %s',
    input => {
      expect(isHttpUrl(input)).toBe(false)
    },
  )
})

describe('classifyInputs', () => {
  it('routes a document with proxies to Clash', () => {
    const value = { proxies: [] }
    expect(classifyInputs([{ source: 'a.yaml', value }])).toEqual({ clash: [value], singbox: [] })
  })

  it.each(['log', 'dns', 'inbounds', 'outbounds', 'route'])('routes a document with %s to sing-box', key => {
    const value = { [key]: {} }
    expect(classifyInputs([{ source: 'a.json', value }])).toEqual({ clash: [], singbox: [value] })
  })

  it('rejects a document that is neither, instead of silently treating it as Clash', () => {
    expect(() => classifyInputs([{ source: 'mystery.yaml', value: { something: 1 } }])).toThrow(
      /mystery\.yaml is neither/,
    )
  })
})

describe('main', () => {
  it('converts a Clash file to stdout', async () => {
    const dir = await makeTempDir()
    const input = join(dir, 'clash.yaml')
    await writeFile(input, CLASH_YAML)
    const { stdout } = captureStreams()

    const code = await main(['node', 'clash2sing-box', 'convert', input])

    expect(code).toBe(0)
    const config = JSON.parse(stdout.join('')) as { outbounds: { tag: string }[] }
    expect(config.outbounds.map(outbound => outbound.tag)).toEqual(['proxy', 'urltest-proxy', 'test-ss'])
  })

  it('writes to the file given by --output', async () => {
    const dir = await makeTempDir()
    const input = join(dir, 'clash.yaml')
    const output = join(dir, 'sing-box.json')
    await writeFile(input, CLASH_YAML)
    captureStreams()

    const code = await main(['node', 'clash2sing-box', 'convert', input, '-o', output])

    expect(code).toBe(0)
    expect(JSON.parse(await readFile(output, 'utf-8'))).toHaveProperty('outbounds')
  })

  it('reports a missing input file and exits non-zero', async () => {
    const { stderr } = captureStreams()

    const code = await main(['node', 'clash2sing-box', 'convert', join(await makeTempDir(), 'nope.yaml')])

    expect(code).toBe(1)
    expect(stderr.join('')).toContain('clash2sing-box:')
  })

  it('rejects a non-numeric --outbound-selector-default instead of silently using index 0', async () => {
    const dir = await makeTempDir()
    const input = join(dir, 'clash.yaml')
    await writeFile(input, CLASH_YAML)
    const { stderr } = captureStreams()

    const code = await main(['node', 'clash2sing-box', 'convert', input, '--outbound-selector-default', 'abc'])

    expect(code).toBe(1)
    expect(stderr.join('')).toContain('--outbound-selector-default')
  })

  it('prints conversion warnings to stderr, not stdout', async () => {
    const dir = await makeTempDir()
    const input = join(dir, 'clash.yaml')
    await writeFile(
      input,
      `proxies:
  - name: bad-hy
    type: hysteria
    server: 1.2.3.4
    port: 443
    protocol: faketcp
    up: "100"
    down: "200"
${CLASH_YAML.slice('proxies:\n'.length)}`,
    )
    const { stdout, stderr } = captureStreams()

    const code = await main(['node', 'clash2sing-box', 'convert', input])

    expect(code).toBe(0)
    expect(stderr.join('')).toContain('does not support the Hysteria protocol "faketcp"')
    // The rest of the subscription still converts.
    const config = JSON.parse(stdout.join('')) as { outbounds: { tag: string }[] }
    expect(config.outbounds.map(outbound => outbound.tag)).toContain('test-ss')
  })
})
