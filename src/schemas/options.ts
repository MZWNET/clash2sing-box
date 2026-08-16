import { z } from 'zod'

/** Conversion options accepted by the library. */
export const Options = z.object({
  outbound: z
    .object({
      domainresolver: z
        .object({
          tag: z.string().optional(),
        })
        .optional(),
      selector: z
        .object({
          default: z.number().int().optional(),
          tag: z.array(z.string()).optional(),
        })
        .optional(),
    })
    .optional(),
})

export type Options = z.infer<typeof Options>

/**
 * Commander hands back a flat, camel-cased bag of strings. Parsing it through a schema
 * replaces the hand-rolled `!== undefined` chains and casts, and — unlike `Number()` —
 * rejects `--outbound-selector-default abc` instead of silently coercing it to `NaN`,
 * which `Array.prototype.at` would then read as index 0.
 */
export const CliOptions = z
  .object({
    output: z.string().optional(),
    outboundDomainresolverTag: z.string().optional(),
    outboundSelectorDefault: z.coerce.number({ error: 'must be an integer' }).int('must be an integer').optional(),
    outboundSelectorTag: z.array(z.string()).optional(),
  })
  .transform(raw => ({
    output: raw.output,
    options: {
      outbound:
        raw.outboundDomainresolverTag === undefined &&
        raw.outboundSelectorDefault === undefined &&
        raw.outboundSelectorTag === undefined
          ? undefined
          : {
              domainresolver:
                raw.outboundDomainresolverTag === undefined ? undefined : { tag: raw.outboundDomainresolverTag },
              selector:
                raw.outboundSelectorDefault === undefined && raw.outboundSelectorTag === undefined
                  ? undefined
                  : { default: raw.outboundSelectorDefault, tag: raw.outboundSelectorTag },
            },
    } satisfies Options,
  }))
