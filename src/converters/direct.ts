import type { z } from 'zod'
import { ClashProxyDirect } from '../schemas/clash.ts'
import { SingboxOutboundDirect } from '../schemas/singbox.ts'
import { convertDialFields } from './shared.ts'

export const DirectPipeline = ClashProxyDirect.transform((proxy): z.input<typeof SingboxOutboundDirect> => ({
  type: 'direct' as const,
  tag: proxy.name,
  ...convertDialFields(proxy),
})).pipe(SingboxOutboundDirect)
