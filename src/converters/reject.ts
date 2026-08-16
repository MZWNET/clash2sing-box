import type { z } from 'zod'
import { ClashProxyReject } from '../schemas/clash.ts'
import { SingboxOutboundBlock } from '../schemas/singbox.ts'

/**
 * sing-box's `block` outbound takes no fields at all, so mihomo's dial options are
 * parsed for leniency but deliberately not carried over.
 */
export const RejectPipeline = ClashProxyReject.transform((proxy): z.input<typeof SingboxOutboundBlock> => ({
  type: 'block' as const,
  tag: proxy.name,
})).pipe(SingboxOutboundBlock)
