// @nvault/client — typed TypeScript SDK for the nvault zero-knowledge secrets
// + parameter platform. Transport (NvaultClient) and E2EE (sealEnvelope/
// openEnvelope) are wire-compatible with the Go reference implementation; the
// shared types are generated from the Go source by `nvault-schemagen` into
// types.generated.ts, so they can never silently drift.
export * from "./types.generated.js";
export { NvaultClient, NvaultError } from "./client.js";
export type {
  NvaultClientOptions,
  PullPageOptions,
  PushOptions,
} from "./client.js";
export {
  generateIdentity,
  sealEnvelope,
  rewrapEnvelope,
  openEnvelope,
  validateEnvelope,
  parseEnvelopeJSON,
  encodePublicKey,
  encodePrivateKey,
  identityFromPrivateKey,
  identityFromPrivateKeyBytes,
  decodePublicKey,
  AADMismatchError,
  EnvelopeValidationError,
  MAX_AAD_BYTES,
  MAX_PLAINTEXT_BYTES,
  MAX_RECIPIENT_ID_BYTES,
  MAX_RECIPIENTS,
  MAX_ENVELOPE_JSON_BYTES,
} from "./crypto.js";
export type { Identity } from "./crypto.js";
export { cloudAAD } from "./slot.js";
export { parseUnambiguousJSON } from "./strictJson.js";
export {
  MAX_HOSTED_ENVELOPE_BYTES,
  MAX_HOSTED_PLAINTEXT_BYTES,
  MAX_HOSTED_PULL_RESPONSE_BYTES,
  MAX_HOSTED_SYNC_BODY_BYTES,
} from "./limits.js";
