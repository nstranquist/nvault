// @nvault/client — typed TypeScript SDK for the nvault zero-knowledge secrets
// + parameter platform. Transport (NvaultClient) and E2EE (sealEnvelope/
// openEnvelope) are wire-compatible with the Go reference implementation; the
// shared types are generated from the Go source by `nvault-schemagen` into
// types.generated.ts, so they can never silently drift.
export * from "./types.generated.js";
export { NvaultClient, NvaultError } from "./client.js";
export type { NvaultClientOptions } from "./client.js";
export {
  generateIdentity,
  sealEnvelope,
  openEnvelope,
  encodePublicKey,
  decodePublicKey,
} from "./crypto.js";
export type { Identity } from "./crypto.js";
