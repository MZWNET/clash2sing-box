import { z } from 'zod'

/**
 * Conversion options accepted by the library.
 *
 * A plain type rather than a schema: nothing ever parses it. `convert` reads these fields
 * directly, and the only untrusted source of them — the CLI's string bag — is validated
 * by `CliOptions` below.
 */
export interface Options {
  outbound?: {
    domainresolver?: { tag?: string }
    selector?: {
      default?: number
      tag?: string[]
    }
  }
}

/**
 * clerc hands back a flat, camel-cased bag of strings. Parsing it through a schema
 * replaces the hand-rolled `!== undefined` chains and casts, and — unlike `Number()` —
 * rejects `--outbound-selector-default abc` instead of silently coercing it to `NaN`,
 * which `Array.prototype.at` would then read as index 0.
 *
 * Unknown keys are stripped, so clerc's own aliases and the `--help`/`--version` flags its
 * plugins register can be handed over without filtering.
 *
 * Every string flag rejects the empty string, because that is what a value-less `--flag` at
 * the end of the line parses to. Left alone it is worse than a missing flag: `Number('')` is
 * `0`, so `--outbound-selector-default` would quietly select the first outbound, and an empty
 * resolver tag would emit `domain_resolver: { server: '' }`.
 */
export const CliOptions = z
  .object({
    output: z.string().min(1, 'must not be empty').optional(),
    outboundDomainresolverTag: z.string().min(1, 'must not be empty').optional(),
    // A negative ordinal is meaningful — `convert` indexes with `Array.prototype.at`.
    outboundSelectorDefault: z
      .string()
      .regex(/^[+-]?\d+$/, 'must be an integer')
      .transform(Number)
      .optional(),
    outboundSelectorTag: z
      .array(z.string())
      .optional()
      .transform(tags => {
        // `--outbound-selector-tag a,b` and `--outbound-selector-tag a --outbound-selector-tag b`
        // both mean the same two tags.
        const split = tags?.flatMap(tag => tag.split(',')).filter(tag => tag !== '')
        // clerc materializes an unpassed array flag as `[]`, and `convert` falls back with
        // `??` — an empty array would mean "emit no selector at all" rather than "not given".
        return split === undefined || split.length === 0 ? undefined : split
      }),
  })
  .transform(raw => ({
    output: raw.output,
    // `convert` reaches every field through optional chaining, so these can be built
    // unconditionally: a flag the user did not pass simply stays `undefined`.
    options: {
      outbound: {
        domainresolver: { tag: raw.outboundDomainresolverTag },
        selector: { default: raw.outboundSelectorDefault, tag: raw.outboundSelectorTag },
      },
    } satisfies Options,
  }))
