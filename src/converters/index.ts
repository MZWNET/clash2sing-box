import type { SingboxAnyOutbound } from '../schemas/singbox.ts'
import type { ConvertedProxy } from './envelope.ts'
import { z } from 'zod'
import { AnyTlsPipeline } from './anytls.ts'
import { DirectPipeline } from './direct.ts'
import { asChain, asEndpoint, asOutbound } from './envelope.ts'
import { HttpPipeline } from './http.ts'
import { HysteriaPipeline } from './hysteria.ts'
import { Hysteria2Pipeline } from './hysteria2.ts'
import { OpenVPNPipeline } from './openvpn.ts'
import { RejectPipeline } from './reject.ts'
import { ShadowsocksPipeline } from './shadowsocks.ts'
import { SnellPipeline } from './snell.ts'
import { Socks5Pipeline } from './socks.ts'
import { SSHPipeline } from './ssh.ts'
import { TailscalePipeline } from './tailscale.ts'
import { TrojanPipeline } from './trojan.ts'
import { TUICPipeline } from './tuic.ts'
import { VLESSPipeline } from './vless.ts'
import { VmessPipeline } from './vmess.ts'
import { WireGuardPipeline } from './wireguard.ts'

/**
 * Every supported protocol, as a single schema mapping a Clash proxy to the sing-box
 * outbounds and endpoints it becomes.
 *
 * One `safeParse` covers all four outcomes, so unsupported protocols, unsupported options
 * and malformed entries all take the same skip-with-a-warning path:
 *
 * - a supported, well-formed proxy      → the converted outbound(s)/endpoint
 * - an unsupported option (e.g. faketcp) → a `custom` issue raised by the converter
 * - an unknown `type`                    → an `invalid_union` discriminator issue
 * - a malformed proxy                    → the usual field-level issues
 */
/** Shadowsocks yields a second outbound when ShadowTLS is in play. */
function shadowsocksEnvelope(result: {
  outbound: SingboxAnyOutbound
  shadowTls?: SingboxAnyOutbound | undefined
}): ConvertedProxy {
  return result.shadowTls === undefined ? asOutbound(result.outbound) : asChain(result.outbound, result.shadowTls)
}

export const ProxyToOutbound = z.discriminatedUnion('type', [
  AnyTlsPipeline.transform(asOutbound),
  DirectPipeline.transform(asOutbound),
  RejectPipeline.transform(asOutbound),
  HttpPipeline.transform(asOutbound),
  HysteriaPipeline.transform(asOutbound),
  Hysteria2Pipeline.transform(asOutbound),
  ShadowsocksPipeline.transform(shadowsocksEnvelope),
  SnellPipeline.transform(asOutbound),
  Socks5Pipeline.transform(asOutbound),
  SSHPipeline.transform(asOutbound),
  TrojanPipeline.transform(asOutbound),
  TUICPipeline.transform(asOutbound),
  VmessPipeline.transform(asOutbound),
  VLESSPipeline.transform(asOutbound),
  WireGuardPipeline.transform(asEndpoint),
  TailscalePipeline.transform(asEndpoint),
  OpenVPNPipeline.transform(asEndpoint),
])

export {
  AnyTlsPipeline,
  DirectPipeline,
  HttpPipeline,
  Hysteria2Pipeline,
  HysteriaPipeline,
  ShadowsocksPipeline,
  SnellPipeline,
  Socks5Pipeline,
  SSHPipeline,
  TrojanPipeline,
  TUICPipeline,
  VLESSPipeline,
  OpenVPNPipeline,
  RejectPipeline,
  TailscalePipeline,
  VmessPipeline,
  WireGuardPipeline,
}
