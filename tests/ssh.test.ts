import type { z } from 'zod'
import type { ClashProxySSH } from '../src/libs/types.ts'
import { doConvertSSH } from '../src/libs/converters/ssh.ts'

type SSHProxy = z.infer<typeof ClashProxySSH>

function makeSSHProxy(overrides: Partial<SSHProxy> = {}): SSHProxy {
  return {
    name: 'test-ssh',
    server: '1.2.3.4',
    port: 22,
    type: 'ssh',
    username: 'root',
    ...overrides,
  }
}

describe('doConvertSSH', () => {
  it('converts basic fields: username → user, name → tag', () => {
    const result = doConvertSSH(makeSSHProxy())
    expect(result).toEqual({
      type: 'ssh',
      tag: 'test-ssh',
      server: '1.2.3.4',
      server_port: 22,
      user: 'root',
    })
  })

  it('includes optional password', () => {
    const result = doConvertSSH(makeSSHProxy({ password: 'secret' }))
    expect(result.password).toBe('secret')
  })

  it('does not include password when undefined', () => {
    const result = doConvertSSH(makeSSHProxy())
    expect(result.password).toBeUndefined()
  })

  it('maps private-key to private_key', () => {
    const result = doConvertSSH(
      makeSSHProxy({ 'private-key': '-----BEGIN OPENSSH PRIVATE KEY-----' }),
    )
    expect(result.private_key).toBe('-----BEGIN OPENSSH PRIVATE KEY-----')
  })

  it('maps private-key-passphrase to private_key_passphrase', () => {
    const result = doConvertSSH(
      makeSSHProxy({ 'private-key-passphrase': 'my-passphrase' }),
    )
    expect(result.private_key_passphrase).toBe('my-passphrase')
  })

  it('maps host-key to host_key', () => {
    const hostKeys = ['ssh-rsa AAAA...']
    const result = doConvertSSH(makeSSHProxy({ 'host-key': hostKeys }))
    expect(result.host_key).toEqual(hostKeys)
  })

  it('maps host-key-algorithms to host_key_algorithms', () => {
    const algorithms = ['ssh-rsa', 'ssh-ed25519']
    const result = doConvertSSH(
      makeSSHProxy({ 'host-key-algorithms': algorithms }),
    )
    expect(result.host_key_algorithms).toEqual(algorithms)
  })

  it('maps interface-name to bind_interface', () => {
    const result = doConvertSSH(
      makeSSHProxy({ 'interface-name': 'eth0' }),
    )
    expect(result.bind_interface).toBe('eth0')
  })

  it('maps routing-mark to routing_mark', () => {
    const result = doConvertSSH(makeSSHProxy({ 'routing-mark': 100 }))
    expect(result.routing_mark).toBe(100)
  })

  it('maps tfo to tcp_fast_open', () => {
    const result = doConvertSSH(makeSSHProxy({ tfo: true }))
    expect(result.tcp_fast_open).toBe(true)
  })

  it('maps mptcp to tcp_multi_path', () => {
    const result = doConvertSSH(makeSSHProxy({ mptcp: true }))
    expect(result.tcp_multi_path).toBe(true)
  })

  it('maps dialer-proxy to detour', () => {
    const result = doConvertSSH(
      makeSSHProxy({ 'dialer-proxy': 'proxy-chain' }),
    )
    expect(result.detour).toBe('proxy-chain')
  })
})
