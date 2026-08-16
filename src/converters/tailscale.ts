import type { z } from 'zod'
import { omitUndefined } from '../object.ts'
import { ClashProxyTailscale } from '../schemas/clash.ts'
import { SingboxEndpointTailscale } from '../schemas/singbox.ts'
import { convertDialFields } from './shared.ts'

/**
 * Tailscale converts to an `endpoints` entry. It has no `network` field: the dial fields
 * here only govern how it reaches the coordination server, not the tunnelled traffic.
 */
export const TailscalePipeline = ClashProxyTailscale.transform((proxy): z.input<typeof SingboxEndpointTailscale> =>
  omitUndefined({
    type: 'tailscale' as const,
    tag: proxy.name,
    ...convertDialFields(proxy),
    auth_key: proxy['auth-key'],
    control_url: proxy['control-url'],
    state_directory: proxy['state-dir'],
    ephemeral: proxy.ephemeral,
    hostname: proxy.hostname,
    accept_routes: proxy['accept-routes'],
    exit_node: proxy['exit-node'],
    exit_node_allow_lan_access: proxy['exit-node-allow-lan-access'],
  }),
).pipe(SingboxEndpointTailscale)
