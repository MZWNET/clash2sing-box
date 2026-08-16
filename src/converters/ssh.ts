import type { z } from 'zod'
import { omitUndefined } from '../object.ts'
import { ClashProxySSH } from '../schemas/clash.ts'
import { SingboxOutboundSSH } from '../schemas/singbox.ts'
import { convertDialFields } from './shared.ts'

export const SSHPipeline = ClashProxySSH.transform((proxy): z.input<typeof SingboxOutboundSSH> =>
  omitUndefined({
    type: 'ssh' as const,
    tag: proxy.name,
    server: proxy.server,
    server_port: proxy.port,
    ...convertDialFields(proxy),
    user: proxy.username,
    password: proxy.password,
    private_key: proxy['private-key'],
    private_key_passphrase: proxy['private-key-passphrase'],
    host_key: proxy['host-key'],
    host_key_algorithms: proxy['host-key-algorithms'],
  }),
).pipe(SingboxOutboundSSH)
