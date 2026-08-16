import type { z } from 'zod'
import { omitUndefined } from '../object.ts'
import { ClashProxyDirect } from '../schemas/clash.ts'
import { SingboxOutboundDirect } from '../schemas/singbox.ts'
import { convertDialFields } from './shared.ts'

export const DirectPipeline = ClashProxyDirect.transform((proxy): z.input<typeof SingboxOutboundDirect> =>
  omitUndefined({
    type: 'direct' as const,
    tag: proxy.name,
    ...convertDialFields(proxy),
  }),
).pipe(SingboxOutboundDirect)
