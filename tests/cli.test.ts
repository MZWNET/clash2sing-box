import { execFile } from 'node:child_process'
import { mkdtemp, readFile, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import process from 'node:process'
import { fileURLToPath } from 'node:url'
import { promisify } from 'node:util'
import { classifyInputs, isHttpUrl, main } from '../src/cli.ts'

async function makeTempDir(): Promise<string> {
  return mkdtemp(join(tmpdir(), 'clash2sing-box-'))
}

const execFileAsync = promisify(execFile)
const CLI = fileURLToPath(new URL('../src/cli.ts', import.meta.url))

/**
 * Error paths have to run out-of-process: `friendlyErrorPlugin` reports a failure by calling
 * `process.exit(1)`, which in-process would take the vitest worker down with it rather than
 * fail the test. Successful runs never reach it, so those stay in-process for coverage.
 */
async function runCli(args: string[]): Promise<{ code: number; stdout: string; stderr: string }> {
  try {
    const { stdout, stderr } = await execFileAsync(process.execPath, ['--experimental-strip-types', CLI, ...args])
    return { code: 0, stdout, stderr }
  } catch (error) {
    const failure = error as { code?: number; stdout?: string; stderr?: string }
    return { code: failure.code ?? 1, stdout: failure.stdout ?? '', stderr: failure.stderr ?? '' }
  }
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

    const code = await main(['convert', input])

    expect(code).toBe(0)
    const config = JSON.parse(stdout.join('')) as { outbounds: { tag: string }[] }
    expect(config.outbounds.map(outbound => outbound.tag)).toEqual(['proxy', 'urltest-proxy', 'test-ss'])
  })

  // An unpassed `[String]` flag arrives as `[]`, which `convert` would read as "emit no
  // selector at all" — the assertion above is what catches that, so keep it exact.
  it.each([
    [
      ['--outbound-selector-tag', 'a,b'],
      ['a', 'b'],
    ],
    [
      ['--outbound-selector-tag', 'a', '--outbound-selector-tag', 'b'],
      ['a', 'b'],
    ],
    [
      ['--outbound-selector-tag', 'a,b', '--outbound-selector-tag', 'c'],
      ['a', 'b', 'c'],
    ],
  ])('accepts --outbound-selector-tag as %j', async (flags, expected) => {
    const dir = await makeTempDir()
    const input = join(dir, 'clash.yaml')
    await writeFile(input, CLASH_YAML)
    const { stdout } = captureStreams()

    const code = await main(['convert', input, ...flags])

    expect(code).toBe(0)
    const config = JSON.parse(stdout.join('')) as { outbounds: { tag: string }[] }
    expect(config.outbounds.map(outbound => outbound.tag).slice(0, expected.length)).toEqual(expected)
  })

  it('writes to the file given by --output', async () => {
    const dir = await makeTempDir()
    const input = join(dir, 'clash.yaml')
    const output = join(dir, 'sing-box.json')
    await writeFile(input, CLASH_YAML)
    captureStreams()

    const code = await main(['convert', input, '-o', output])

    expect(code).toBe(0)
    expect(JSON.parse(await readFile(output, 'utf-8'))).toHaveProperty('outbounds')
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

    const code = await main(['convert', input])

    expect(code).toBe(0)
    expect(stderr.join('')).toContain('does not support the Hysteria protocol "faketcp"')
    // The rest of the subscription still converts.
    const config = JSON.parse(stdout.join('')) as { outbounds: { tag: string }[] }
    expect(config.outbounds.map(outbound => outbound.tag)).toContain('test-ss')
  })
})

describe('failures', () => {
  it('reports a missing input file and exits non-zero', async () => {
    const { code, stderr } = await runCli(['convert', join(await makeTempDir(), 'nope.yaml')])

    expect(code).toBe(1)
    expect(stderr).toContain('clash2sing-box:')
  })

  it('rejects a non-numeric --outbound-selector-default instead of silently using index 0', async () => {
    const dir = await makeTempDir()
    const input = join(dir, 'clash.yaml')
    await writeFile(input, CLASH_YAML)

    const { code, stderr } = await runCli(['convert', input, '--outbound-selector-default', 'abc'])

    expect(code).toBe(1)
    expect(stderr).toContain('--outbound-selector-default')
  })

  it('rejects an unknown flag instead of silently ignoring the typo', async () => {
    const dir = await makeTempDir()
    const input = join(dir, 'clash.yaml')
    await writeFile(input, CLASH_YAML)

    const { code, stderr } = await runCli(['convert', input, '--outbund-selector-tag', 'proxy'])

    expect(code).toBe(1)
    // clerc names the flag by its normalized key, not the dashed form that was typed.
    expect(stderr).toContain('Unexpected flag: outbundSelectorTag')
  })

  // A flag left without a value at the end of the line parses to the empty string, which
  // `Number('')` would turn into a silent index 0 rather than an error.
  it.each([
    ['--outbound-selector-default', 'must be an integer'],
    ['--outbound-domainresolver-tag', 'must not be empty'],
    ['--output', 'must not be empty'],
  ])('rejects a value-less %s', async (flag, message) => {
    const dir = await makeTempDir()
    const input = join(dir, 'clash.yaml')
    await writeFile(input, CLASH_YAML)

    const { code, stderr } = await runCli(['convert', input, flag])

    expect(code).toBe(1)
    expect(stderr).toContain(`${flag} ${message}`)
  })

  it('suggests the closest command for a mistyped one', async () => {
    const { code, stderr } = await runCli(['convrt'])

    expect(code).toBe(1)
    expect(stderr).toContain('Did you mean "convert"?')
  })
})
