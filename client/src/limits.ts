/**
 * Hosted transport limits.
 *
 * These are stricter than the portable envelope format. The managed backend
 * stores an envelope in one Convex document, so encrypted data, base64 growth,
 * metadata, and recipient stanzas must all remain below 1 MiB.
 */
export const MAX_HOSTED_PLAINTEXT_BYTES = 256 << 10;
export const MAX_HOSTED_ENVELOPE_BYTES = 900 << 10;
export const MAX_HOSTED_SYNC_BODY_BYTES = 2 << 20;
export const MAX_HOSTED_PULL_RESPONSE_BYTES = 12 << 20;
