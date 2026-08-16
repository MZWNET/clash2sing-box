import { z } from 'zod'
import { omitUndefined } from '../object.ts'
import { ClashProxyShadowsocks } from '../schemas/clash.ts'
import { SingboxOutboundShadowsocks, SingboxOutboundShadowTLS } from '../schemas/singbox.ts'
import { convertDialFields, convertMultiplex, convertNetwork } from './shared.ts'

type ShadowsocksProxy = z.infer<typeof ClashProxyShadowsocks>

/**
 * Clash folds ShadowTLS into the inner proxy as a SIP003-style plugin, while sing-box
 * models it as a standalone outbound — it is a protocol-agnostic TLS masquerade with no
 * encryption of its own, so one implementation serves every inner protocol. Converting
 * therefore produces two outbounds joined by `detour`.
 */
const ShadowsocksResult = z.object({
  outbound: SingboxOutboundShadowsocks,
  shadowTls: SingboxOutboundShadowTLS.optional(),
})

/** sing-box takes plugin options as a single `key=value;flag` string. */
function buildPluginOpts(proxy: ShadowsocksProxy): string | undefined {
  if (proxy.plugin === undefined || proxy.plugin === 'shadow-tls') {
    return undefined
  }

  const opts = proxy['plugin-opts']
  if (opts === undefined) {
    return ''
  }

  const parts: string[] = []
  if (opts.mode !== undefined) {
    parts.push(`mode=${opts.mode}`)
  }
  if (opts.host !== undefined) {
    parts.push(`host=${opts.host}`)
  }
  if (proxy.plugin === 'v2ray-plugin') {
    if (opts.tls === true) {
      parts.push('tls')
    }
    if (opts.path !== undefined) {
      parts.push(`path=${opts.path}`)
    }
    if (opts.mux !== undefined) {
      parts.push(`mux=${opts.mux.toString()}`)
    }
  }
  return parts.join(';')
}

function udpOverTcp(proxy: ShadowsocksProxy): { enabled: boolean; version?: 1 | 2 | undefined } | undefined {
  return proxy['udp-over-tcp'] === true ? { enabled: true, version: proxy['udp-over-tcp-version'] } : undefined
}

export const ShadowsocksPipeline = ClashProxyShadowsocks.transform((proxy, ctx): z.input<typeof ShadowsocksResult> => {
  if (proxy.plugin === 'shadow-tls') {
    const opts = proxy['plugin-opts']
    const version = opts?.version ?? 1
    if (version !== 1 && version !== 2 && version !== 3) {
      ctx.addIssue({
        code: 'custom',
        message: `sing-box does not support ShadowTLS version ${version.toString()}`,
      })
      return z.NEVER
    }

    const shellTag = `${proxy.name}-shadowtls`
    const fingerprint = proxy['client-fingerprint']
    return {
      outbound: omitUndefined({
        type: 'shadowsocks' as const,
        tag: proxy.name,
        method: proxy.cipher,
        password: proxy.password,
        multiplex: convertMultiplex(proxy.smux),
        udp_over_tcp: udpOverTcp(proxy),
        // Reaches the server through the ShadowTLS shell, so it carries no address of
        // its own. Any `dialer-proxy` belongs on the shell, which does the real dialing.
        detour: shellTag,
        network: convertNetwork(proxy),
      }),
      shadowTls: omitUndefined({
        type: 'shadowtls' as const,
        tag: shellTag,
        server: proxy.server,
        server_port: proxy.port,
        ...convertDialFields(proxy),
        version,
        password: opts?.password,
        tls: omitUndefined({
          enabled: true,
          server_name: opts?.host,
          utls: fingerprint === undefined ? undefined : { enabled: true, fingerprint },
        }),
      }),
    }
  }

  return {
    outbound: omitUndefined({
      type: 'shadowsocks' as const,
      tag: proxy.name,
      server: proxy.server,
      server_port: proxy.port,
      ...convertDialFields(proxy),
      network: convertNetwork(proxy),
      method: proxy.cipher,
      password: proxy.password,
      // Clash calls the simple-obfs plugin `obfs`; sing-box calls it `obfs-local`.
      plugin: proxy.plugin === 'obfs' ? 'obfs-local' : proxy.plugin,
      plugin_opts: buildPluginOpts(proxy),
      multiplex: convertMultiplex(proxy.smux),
      udp_over_tcp: udpOverTcp(proxy),
    }),
  }
}).pipe(ShadowsocksResult)
