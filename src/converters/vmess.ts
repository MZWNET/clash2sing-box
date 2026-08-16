import type { z } from 'zod'
import { omitUndefined } from '../object.ts'
import { ClashProxyVmess } from '../schemas/clash.ts'
import { SingboxOutboundVmess } from '../schemas/singbox.ts'
import { convertDialFields, convertMultiplex, convertNetwork, convertTLSTransport, convertTransport } from './shared.ts'

export const VmessPipeline = ClashProxyVmess.transform((proxy): z.input<typeof SingboxOutboundVmess> =>
  omitUndefined({
    type: 'vmess' as const,
    tag: proxy.name,
    server: proxy.server,
    server_port: proxy.port,
    ...convertDialFields(proxy),
    network: convertNetwork(proxy),
    uuid: proxy.uuid,
    security: proxy.cipher,
    alter_id: proxy.alterId,
    global_padding: proxy['global-padding'],
    authenticated_length: proxy['authenticated-length'],
    packet_encoding: proxy['packet-encoding'],
    transport: convertTransport(proxy),
    multiplex: convertMultiplex(proxy.smux),
    tls: proxy.tls === true ? convertTLSTransport(proxy) : undefined,
  }),
).pipe(SingboxOutboundVmess)
