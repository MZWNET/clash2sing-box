import { deepmerge } from 'deepmerge-ts'

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

/**
 * Recursively drop keys whose value is `undefined`.
 *
 * Converters build plain object literals and let absent fields flow through as `undefined`,
 * which keeps them free of the `if (x !== undefined) out.y = x` boilerplate. `ProxyToOutbound`
 * runs this once over each converted proxy so consumers never see keys with `undefined` values.
 */
export function omitUndefined<T>(value: T): T {
  if (Array.isArray(value)) {
    return (value as unknown[]).map(item => omitUndefined(item)) as T
  }
  if (!isPlainObject(value)) {
    return value
  }

  const result: Record<string, unknown> = {}
  for (const [key, item] of Object.entries(value)) {
    if (item !== undefined) {
      result[key] = omitUndefined(item)
    }
  }
  return result as T
}

/** Deep-merge objects, concatenating arrays. `deepmerge` itself needs at least one argument. */
export function merge(...objects: object[]): Record<string, unknown> {
  return objects.length === 0 ? {} : (deepmerge(...objects) as Record<string, unknown>)
}
