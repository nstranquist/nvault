import { MAX_AAD_BYTES } from "./crypto.js";

/** Return the canonical authenticated slot used by nvault Cloud. */
export function cloudAAD(
  org: string,
  env: string,
  scope: string,
  key: string,
): string {
  for (const [name, value] of [
    ["organization", org],
    ["environment", env],
    ["scope", scope],
    ["key", key],
  ] as const) {
    if (!value) throw new Error(`${name} is required`);
    if (value.includes("/") || value.includes("\0")) {
      throw new Error(`${name} must be one path segment`);
    }
  }
  const aad = `${org}/${env}/${scope}/${key}`;
  if (new TextEncoder().encode(aad).length > MAX_AAD_BYTES) {
    throw new Error("cloud slot exceeds the associated-data size limit");
  }
  return aad;
}
