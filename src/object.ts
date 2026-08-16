import { deepmerge } from 'deepmerge-ts'

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

/**
 * Recursively drop keys whose value is `undefined`.
 *
 * Converters build plain object literals and let absent fields flow through as `undefined`,
 * which keeps them free of the `if (x !== undefined) out.y = x` boilerplate. This runs once
 * at the end of the pipeline so consumers never see keys with `undefined` values.
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

/** Deep-merge objects, concatenating arrays. Empty objects are ignored. */
export function merge(...objects: object[]): Record<string, unknown> {
  const objectsToMerge = objects.filter(obj => Object.keys(obj).length > 0)
  if (objectsToMerge.length === 0) {
    return {}
  }
  return deepmerge(...objectsToMerge) as Record<string, unknown>
}
