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
    /**
     * Extra proxy groups, each collecting the outbounds whose tag `match` accepts. Already
     * compiled: `CliOptions` is the only place that turns a pattern string into a `RegExp`,
     * so there is a single construction and a single error message.
     */
    group?: { tag: string; match: RegExp }[]
    /**
     * Tags to keep out of every URLTest group. For an outbound you pick deliberately rather
     * than by latency — WARP, a relay — winning a race it should not be in silently
     * captures the default route.
     */
    noUrltest?: string[]
    selector?: {
      default?: number
      tag?: string[]
    }
    /**
     * Certificate pinning for the outbounds whose tag `match` accepts.
     *
     * mihomo pins with `fingerprint`, hashing the whole certificate, while sing-box hashes
     * the public key — the two are not interchangeable, so pinning is named here rather
     * than converted. `certificate` holds PEM lines, already read: `convert` never touches
     * the filesystem.
     */
    tls?: {
      certificate?: { match: RegExp; certificate: string[] }[]
      certificatePublicKeySha256?: { match: RegExp; hash: string }[]
    }
  }
}

/**
 * `--flag a,b` and `--flag a --flag b` mean the same two tags.
 *
 * clerc materializes an unpassed array flag as `[]`, and `convert` falls back with `??`, so
 * an empty result has to come back as `undefined`: for `--outbound-selector-tag` an empty
 * array would mean "emit no selector at all" rather than "not given".
 */
function splitTags(tags: string[] | undefined): string[] | undefined {
  const split = tags?.flatMap(tag => tag.split(',')).filter(tag => tag !== '')
  return split === undefined || split.length === 0 ? undefined : split
}

/**
 * Options naming a file rather than carrying a value. The CLI reads them, which is what
 * keeps `convert` synchronous and free of file and network access.
 */
export interface OptionFiles {
  entryGeoDb?: string | undefined
  tlsCertificate?: { match: RegExp; path: string }[] | undefined
}

interface Pair {
  left: string
  right: string
  entry: string
}

/**
 * Split `left=right` entries on the *first* `=`, which leaves the right-hand side free to
 * contain one — a regex lookahead, a filesystem path and base64 padding all do. A pattern
 * on the left therefore writes a literal `=` as `\x3d`.
 */
function splitPairs(entries: string[] | undefined, shape: string, ctx: z.RefinementCtx): Pair[] | undefined {
  if (entries === undefined || entries.length === 0) {
    return undefined
  }

  const pairs: Pair[] = []
  for (const entry of entries) {
    const separator = entry.indexOf('=')
    const right = entry.slice(separator + 1)
    // A separator at index 0 means an empty left side.
    if (separator <= 0 || right === '') {
      ctx.addIssue({ code: 'custom', message: `must look like "${shape}", got "${entry}"` })
      continue
    }
    pairs.push({ left: entry.slice(0, separator), right, entry })
  }
  return pairs
}

/**
 * Deliberately flagless. `RegExp.prototype.test` advances `lastIndex` on a `/g/` regex, so a
 * shared instance would match every other candidate.
 */
function compilePattern(pattern: string, entry: string, ctx: z.RefinementCtx): RegExp | undefined {
  try {
    return new RegExp(pattern)
  } catch (error) {
    const reason = error instanceof Error ? error.message : String(error)
    ctx.addIssue({ code: 'custom', message: `has an invalid regex "${pattern}" in "${entry}": ${reason}` })
    return undefined
  }
}

/** `regex=value`, where the regex is matched against outbound tags. */
function matchedValues(
  entries: string[] | undefined,
  shape: string,
  ctx: z.RefinementCtx,
): { match: RegExp; value: string }[] | undefined {
  const pairs = splitPairs(entries, shape, ctx)
  if (pairs === undefined) {
    return undefined
  }

  const specs: { match: RegExp; value: string }[] = []
  for (const { left, right, entry } of pairs) {
    const match = compilePattern(left, entry, ctx)
    if (match !== undefined) {
      specs.push({ match, value: right })
    }
  }
  return specs
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
    outboundEntryGeoDb: z.string().min(1, 'must not be empty').optional(),
    outboundGroup: z
      .array(z.string())
      .optional()
      .transform((entries, ctx) => {
        const pairs = splitPairs(entries, 'tag=regex', ctx)
        if (pairs === undefined) {
          return undefined
        }

        const specs: { tag: string; match: RegExp }[] = []
        for (const { left: tag, right: pattern, entry } of pairs) {
          if (specs.some(spec => spec.tag === tag)) {
            ctx.addIssue({ code: 'custom', message: `was given the tag "${tag}" twice` })
            continue
          }

          const match = compilePattern(pattern, entry, ctx)
          if (match !== undefined) {
            specs.push({ tag, match })
          }
        }
        return specs
      }),
    outboundNoUrltest: z.array(z.string()).optional().transform(splitTags),
    // A negative ordinal is meaningful — `convert` indexes with `Array.prototype.at`.
    outboundSelectorDefault: z
      .string()
      .regex(/^[+-]?\d+$/, 'must be an integer')
      .transform(Number)
      .optional(),
    outboundSelectorTag: z.array(z.string()).optional().transform(splitTags),
    outboundTlsCertificate: z
      .array(z.string())
      .optional()
      .transform((entries, ctx) => matchedValues(entries, 'regex=path', ctx)),
    outboundTlsCertificatePublicKeySha256: z
      .array(z.string())
      .optional()
      .transform((entries, ctx) => matchedValues(entries, 'regex=base64', ctx)),
  })
  .transform(raw => ({
    output: raw.output,
    // These name files, so they stay out of `Options` and off `convert`'s pure path.
    files: {
      entryGeoDb: raw.outboundEntryGeoDb,
      tlsCertificate: raw.outboundTlsCertificate?.map(({ match, value }) => ({ match, path: value })),
    } satisfies OptionFiles,
    // `convert` reaches every field through optional chaining, so these can be built
    // unconditionally: a flag the user did not pass simply stays `undefined`.
    options: {
      outbound: {
        domainresolver: { tag: raw.outboundDomainresolverTag },
        group: raw.outboundGroup,
        noUrltest: raw.outboundNoUrltest,
        selector: { default: raw.outboundSelectorDefault, tag: raw.outboundSelectorTag },
        tls: {
          certificatePublicKeySha256: raw.outboundTlsCertificatePublicKeySha256?.map(({ match, value }) => ({
            match,
            hash: value,
          })),
        },
      },
    } satisfies Options,
  }))
