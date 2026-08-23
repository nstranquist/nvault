// Browser/Node E2EE that is wire-compatible with the Go reference
// implementation in nicos-dev/internal/vault/crypto.
//
// Construction (must match Go exactly):
//   - data key (DEK): 32 random bytes
//   - body: XChaCha20-Poly1305 IETF AEAD, 24-byte nonce, additional data = aad.
//     libsodium's crypto_aead_xchacha20poly1305_ietf is byte-identical to Go's
//     golang.org/x/crypto/chacha20poly1305.NewX (both: HChaCha20 subkey + IETF
//     ChaCha20-Poly1305, combined ciphertext||tag).
//   - per-recipient wrapped key: crypto_box_seal (anonymous sealed box) — this
//     is byte-compatible with Go's nacl/box.SealAnonymous, which derives its box
//     nonce as Blake2b(ephemeralPub || recipientPub) exactly like libsodium. So
//     crypto_box_seal_open on the recipient side opens Go-sealed keys and
//     vice-versa.
//   - Go encodes []byte fields (nonce, ciphertext, wrapped_key) as base64-std in
//     JSON, so we use libsodium base64 variant ORIGINAL (standard + padding).
//
// Single dependency: libsodium-wrappers. Portable across Node and browsers (no
// Buffer / Node globals).
//
// Cross-language interop is asserted by the round-trip test in test/ against the
// Go `nvault` binary. The transport client (./client) needs no crypto and is
// usable independently.
import sodium from "libsodium-wrappers";
import { ENVELOPE_FORMAT_V1, ENVELOPE_ALG_V1 } from "./types.generated.js";
import type { Envelope, Stanza, Recipient } from "./types.generated.js";
import { parseUnambiguousJSON } from "./strictJson.js";

export interface Identity {
  /** nvpub_… encoded public key */
  publicKey: string;
  /** raw 32-byte X25519 private key */
  privateKey: Uint8Array;
}

const PUB_PREFIX = "nvpub_";
const PRIV_PREFIX = "nvpriv_";
const KEY_BYTES = 32;
const NONCE_BYTES = 24;
const TAG_BYTES = 16;
const WRAPPED_KEY_BYTES = 80;
export const MAX_PLAINTEXT_BYTES = 16 << 20;
export const MAX_RECIPIENTS = 1024;
export const MAX_AAD_BYTES = 4096;
export const MAX_RECIPIENT_ID_BYTES = 256;
export const MAX_ENVELOPE_JSON_BYTES = 32 << 20;

const ENVELOPE_FIELDS = new Set([
  "v",
  "alg",
  "nonce",
  "ciphertext",
  "recipients",
  "aad",
]);
const STANZA_FIELDS = new Set(["recipient_id", "wrapped_key"]);

export class EnvelopeValidationError extends Error {
  constructor(message: string) {
    super(`invalid envelope: ${message}`);
    this.name = "EnvelopeValidationError";
  }
}

export class AADMismatchError extends Error {
  constructor() {
    super("envelope associated data does not match expected slot");
    this.name = "AADMismatchError";
  }
}

function b64(b: Uint8Array): string {
  return sodium.to_base64(b, sodium.base64_variants.ORIGINAL);
}
function unb64(s: string): Uint8Array {
  return sodium.from_base64(s, sodium.base64_variants.ORIGINAL);
}

/** Decode the nvpub_… form (base64url, no padding) to raw 32 bytes. */
export function decodePublicKey(s: string): Uint8Array {
  if (typeof s !== "string") throw new Error("public key must be text");
  if (!s.startsWith(PUB_PREFIX)) throw new Error(`public key must start with ${PUB_PREFIX}`);
  let raw: Uint8Array;
  try {
    raw = sodium.from_base64(
      s.slice(PUB_PREFIX.length),
      sodium.base64_variants.URLSAFE_NO_PADDING,
    );
  } catch {
    throw new Error("public key is not canonical base64url");
  }
  if (raw.length !== 32) throw new Error(`public key must be 32 bytes, got ${raw.length}`);
  if (encodePublicKey(raw) !== s) throw new Error("public key is not canonically encoded");
  if (raw.every((byte) => byte === 0)) throw new Error("public key cannot be all zeroes");
  return raw;
}

function byteLength(s: string): number {
  return new TextEncoder().encode(s).length;
}

function decodeEnvelopeBase64(value: unknown, field: string, expected?: number, maximum?: number): Uint8Array {
  if (typeof value !== "string") throw new EnvelopeValidationError(`${field} must be base64 text`);
  if (maximum !== undefined && value.length > Math.ceil(maximum / 3) * 4 + 4) {
    throw new EnvelopeValidationError(`${field} exceeds its size limit`);
  }
  let decoded: Uint8Array;
  try {
    decoded = unb64(value);
  } catch {
    throw new EnvelopeValidationError(`${field} is not canonical base64`);
  }
  if (b64(decoded) !== value) throw new EnvelopeValidationError(`${field} is not canonical base64`);
  if (expected !== undefined && decoded.length !== expected) {
    throw new EnvelopeValidationError(`${field} must be ${expected} bytes, got ${decoded.length}`);
  }
  if (maximum !== undefined && decoded.length > maximum) {
    throw new EnvelopeValidationError(`${field} exceeds ${maximum} bytes`);
  }
  return decoded;
}

function validateRecipients(recipients: Recipient[]): void {
  if (!Array.isArray(recipients) || recipients.length === 0) throw new Error("at least one recipient is required");
  if (recipients.length > MAX_RECIPIENTS) throw new Error(`recipient count exceeds ${MAX_RECIPIENTS}`);
  const seen = new Set<string>();
  for (const [index, recipient] of recipients.entries()) {
    if (!recipient || typeof recipient.id !== "string") throw new Error(`recipient ${index} id must be text`);
    const idBytes = byteLength(recipient.id);
    if (idBytes === 0 || idBytes > MAX_RECIPIENT_ID_BYTES) {
      throw new Error(`recipient ${index} id length is outside [1,${MAX_RECIPIENT_ID_BYTES}]`);
    }
    if (seen.has(recipient.id)) throw new Error(`duplicate recipient id ${JSON.stringify(recipient.id)}`);
    seen.add(recipient.id);
    const publicKey = decodePublicKey(recipient.public_key);
    if (publicKey.every((byte) => byte === 0)) throw new Error(`recipient ${JSON.stringify(recipient.id)} has an all-zero public key`);
  }
}

function validateEnvelopeReady(value: unknown): asserts value is Envelope {
	if (!value || typeof value !== "object" || Array.isArray(value)) throw new EnvelopeValidationError("value must be an object");
	const record = value as Record<string, unknown>;
	const unknownEnvelopeField = Object.keys(record).find(
	  (field) => !ENVELOPE_FIELDS.has(field),
	);
	if (unknownEnvelopeField) {
	  throw new EnvelopeValidationError(
		`unknown field ${JSON.stringify(unknownEnvelopeField)}`,
	  );
	}
  const env = value as Partial<Envelope>;
  if (env.v !== ENVELOPE_FORMAT_V1 || env.alg !== ENVELOPE_ALG_V1) {
    throw new EnvelopeValidationError(`unsupported format ${String(env.v)}/${String(env.alg)}`);
  }
  decodeEnvelopeBase64(env.nonce, "nonce", NONCE_BYTES);
  const ciphertext = decodeEnvelopeBase64(env.ciphertext, "ciphertext", undefined, MAX_PLAINTEXT_BYTES + TAG_BYTES);
  if (ciphertext.length < TAG_BYTES) throw new EnvelopeValidationError(`ciphertext must be at least ${TAG_BYTES} bytes`);
  const aad = env.aad ?? "";
  if (typeof aad !== "string") throw new EnvelopeValidationError("aad must be text");
  if (byteLength(aad) > MAX_AAD_BYTES) throw new EnvelopeValidationError(`aad exceeds ${MAX_AAD_BYTES} bytes`);
  if (!Array.isArray(env.recipients) || env.recipients.length === 0 || env.recipients.length > MAX_RECIPIENTS) {
    throw new EnvelopeValidationError(`recipient count must be in [1,${MAX_RECIPIENTS}]`);
  }
  const seen = new Set<string>();
  for (const [index, stanza] of env.recipients.entries()) {
	if (!stanza || typeof stanza !== "object" || Array.isArray(stanza) || typeof stanza.recipient_id !== "string") {
      throw new EnvelopeValidationError(`recipient ${index} id must be text`);
    }
	const unknownStanzaField = Object.keys(stanza).find(
	  (field) => !STANZA_FIELDS.has(field),
	);
	if (unknownStanzaField) {
	  throw new EnvelopeValidationError(
		`recipient ${index} has unknown field ${JSON.stringify(unknownStanzaField)}`,
	  );
	}
    const idBytes = byteLength(stanza.recipient_id);
    if (idBytes === 0 || idBytes > MAX_RECIPIENT_ID_BYTES) {
      throw new EnvelopeValidationError(`recipient ${index} id length is outside [1,${MAX_RECIPIENT_ID_BYTES}]`);
    }
    if (seen.has(stanza.recipient_id)) throw new EnvelopeValidationError(`duplicate recipient id ${JSON.stringify(stanza.recipient_id)}`);
    seen.add(stanza.recipient_id);
    decodeEnvelopeBase64(stanza.wrapped_key, `recipient ${JSON.stringify(stanza.recipient_id)} wrapped key`, WRAPPED_KEY_BYTES);
  }
}

/** Validate untrusted envelope data and return its narrowed wire type. */
export async function validateEnvelope(value: unknown): Promise<Envelope> {
  await sodium.ready;
  validateEnvelopeReady(value);
  return value;
}

/** Parse and validate an untrusted nvault.enc.v1 JSON envelope. */
export async function parseEnvelopeJSON(raw: string): Promise<Envelope> {
	if (typeof raw !== "string") {
	  throw new EnvelopeValidationError("JSON input must be text");
	}
	if (
	  raw.length > MAX_ENVELOPE_JSON_BYTES ||
	  byteLength(raw) > MAX_ENVELOPE_JSON_BYTES
	) {
	  throw new EnvelopeValidationError(
		`JSON exceeds ${MAX_ENVELOPE_JSON_BYTES} bytes`,
	  );
	}
	let value: unknown;
	try {
	  value = parseUnambiguousJSON(raw, "envelope JSON");
	} catch (error) {
	  throw new EnvelopeValidationError(
		error instanceof Error ? error.message : "JSON is invalid",
	  );
	}
	return validateEnvelope(value);
}

/** Encode raw 32 bytes to the nvpub_… form. */
export function encodePublicKey(raw: Uint8Array): string {
  return PUB_PREFIX + sodium.to_base64(raw, sodium.base64_variants.URLSAFE_NO_PADDING);
}

/** Encode a raw private key for offline backup or transfer. */
export function encodePrivateKey(raw: Uint8Array): string {
  if (!(raw instanceof Uint8Array) || raw.length !== KEY_BYTES) {
    throw new Error(`private key must be ${KEY_BYTES} bytes`);
  }
  // Keep backup encoding synchronous and independent of libsodium's async
  // initialization. This path is used while a browser unlocks a stored key.
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
  let encoded = "";
  for (let index = 0; index < raw.length; index += 3) {
    const first = raw[index];
    const second = index + 1 < raw.length ? raw[index + 1] : 0;
    const third = index + 2 < raw.length ? raw[index + 2] : 0;
    const packed = (first << 16) | (second << 8) | third;
    encoded += alphabet[(packed >>> 18) & 63];
    encoded += alphabet[(packed >>> 12) & 63];
    if (index + 1 < raw.length) encoded += alphabet[(packed >>> 6) & 63];
    if (index + 2 < raw.length) encoded += alphabet[packed & 63];
  }
  return PRIV_PREFIX + encoded;
}

/** Restore an identity from an nvpriv_… private-key backup. */
export async function identityFromPrivateKey(encoded: string): Promise<Identity> {
  await sodium.ready;
  if (typeof encoded !== "string" || !encoded.startsWith(PRIV_PREFIX)) {
    throw new Error(`private key must start with ${PRIV_PREFIX}`);
  }
	let privateKey: Uint8Array;
	try {
	  privateKey = sodium.from_base64(
		encoded.slice(PRIV_PREFIX.length),
		sodium.base64_variants.URLSAFE_NO_PADDING,
	  );
	} catch {
	  throw new Error("private key is not canonical base64url");
	}
	if (privateKey.length !== KEY_BYTES || encodePrivateKey(privateKey) !== encoded) {
	  privateKey.fill(0);
	  throw new Error(`private key must be a canonical ${KEY_BYTES}-byte value`);
	}
	if (privateKey.every((byte) => byte === 0)) {
	  privateKey.fill(0);
	  throw new Error("private key cannot be all zeroes");
	}
  const publicKey = sodium.crypto_scalarmult_base(privateKey);
  return { publicKey: encodePublicKey(publicKey), privateKey };
}

/** Restore an identity from raw private-key bytes without creating a string backup. */
export async function identityFromPrivateKeyBytes(
	raw: Uint8Array,
): Promise<Identity> {
	await sodium.ready;
	if (!(raw instanceof Uint8Array) || raw.length !== KEY_BYTES) {
	  throw new Error(`private key must be ${KEY_BYTES} bytes`);
	}
	if (raw.every((byte) => byte === 0)) {
	  throw new Error("private key cannot be all zeroes");
	}
	const privateKey = new Uint8Array(raw);
	const publicKey = sodium.crypto_scalarmult_base(privateKey);
	return { publicKey: encodePublicKey(publicKey), privateKey };
}

/** Generate a fresh identity (X25519 keypair). */
export async function generateIdentity(): Promise<Identity> {
  await sodium.ready;
  const kp = sodium.crypto_box_keypair();
  return { publicKey: encodePublicKey(kp.publicKey), privateKey: kp.privateKey };
}

/**
 * sealEnvelope encrypts plaintext to every recipient, producing an Envelope that
 * is byte-compatible with the Go reference. `aad` (may be "") is authenticated.
 */
export async function sealEnvelope(
  plaintext: Uint8Array,
  recipients: Recipient[],
  aad = "",
): Promise<Envelope> {
  await sodium.ready;
  if (plaintext.length > MAX_PLAINTEXT_BYTES) throw new Error(`plaintext exceeds ${MAX_PLAINTEXT_BYTES} bytes`);
  if (byteLength(aad) > MAX_AAD_BYTES) throw new Error(`aad exceeds ${MAX_AAD_BYTES} bytes`);
  validateRecipients(recipients);
  const dek = sodium.randombytes_buf(sodium.crypto_aead_xchacha20poly1305_ietf_KEYBYTES);
  const nonce = sodium.randombytes_buf(sodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
  const aadBytes = new TextEncoder().encode(aad);
	try {
	  const ciphertext = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
		plaintext,
		aadBytes,
		null,
		nonce,
		dek,
	  );

	  const stanzas: Stanza[] = recipients
		.map((r): Stanza => {
		  const recipientPub = decodePublicKey(r.public_key);
		  const wrapped = sodium.crypto_box_seal(dek, recipientPub);
		  return { recipient_id: r.id, wrapped_key: b64(wrapped) };
		})
		.sort((a, b) => (a.recipient_id < b.recipient_id ? -1 : a.recipient_id > b.recipient_id ? 1 : 0));

	  return {
		v: ENVELOPE_FORMAT_V1,
		alg: ENVELOPE_ALG_V1,
		nonce: b64(nonce),
		ciphertext: b64(ciphertext),
		recipients: stanzas,
		...(aad ? { aad } : {}),
	  };
	} finally {
	  dek.fill(0);
	}
}

/**
 * Re-seal only the existing data key to a new recipient set. The encrypted body,
 * nonce, and authenticated slot remain unchanged. The function authenticates
 * the body before it returns and clears its temporary plaintext and data-key
 * buffers where the JavaScript runtime permits it.
 */
export async function rewrapEnvelope(
  env: unknown,
  identity: Identity,
  expectedAAD: string,
  recipients: Recipient[],
): Promise<Envelope> {
  await sodium.ready;
  validateEnvelopeReady(env);
  if ((env.aad ?? "") !== expectedAAD) throw new AADMismatchError();
  validateRecipients(recipients);
  const pub = decodePublicKey(identity.publicKey);
  if (
    !(identity.privateKey instanceof Uint8Array) ||
    identity.privateKey.length !== KEY_BYTES
  ) {
    throw new Error(`private key must be ${KEY_BYTES} bytes`);
  }

  let dek: Uint8Array | null = null;
  for (const stanza of env.recipients) {
    try {
      dek = sodium.crypto_box_seal_open(
        decodeEnvelopeBase64(
          stanza.wrapped_key,
          "wrapped key",
          WRAPPED_KEY_BYTES,
        ),
        pub,
        identity.privateKey,
      );
      break;
    } catch {
      // This stanza was sealed to another recipient.
    }
  }
  if (!dek) throw new Error("no recipient stanza decrypts with this identity");

  try {
    const plaintext = sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
      null,
      decodeEnvelopeBase64(
        env.ciphertext,
        "ciphertext",
        undefined,
        MAX_PLAINTEXT_BYTES + TAG_BYTES,
      ),
      new TextEncoder().encode(env.aad ?? ""),
      decodeEnvelopeBase64(env.nonce, "nonce", NONCE_BYTES),
      dek,
    );
    plaintext.fill(0);

    const stanzas = recipients
      .map((recipient): Stanza => {
        const wrapped = sodium.crypto_box_seal(
          dek!,
          decodePublicKey(recipient.public_key),
        );
        return { recipient_id: recipient.id, wrapped_key: b64(wrapped) };
      })
      .sort((a, b) =>
        a.recipient_id < b.recipient_id
          ? -1
          : a.recipient_id > b.recipient_id
            ? 1
            : 0,
      );

    return { ...env, recipients: stanzas };
  } finally {
    dek.fill(0);
  }
}

/**
 * Open an envelope for expectedAAD with the given identity. expectedAAD must
 * come from the requested logical slot, never from the envelope itself.
 */
export async function openEnvelope(env: unknown, identity: Identity, expectedAAD: string): Promise<Uint8Array> {
  await sodium.ready;
  validateEnvelopeReady(env);
  if ((env.aad ?? "") !== expectedAAD) throw new AADMismatchError();
  const pub = decodePublicKey(identity.publicKey);
  if (!(identity.privateKey instanceof Uint8Array) || identity.privateKey.length !== KEY_BYTES) {
    throw new Error(`private key must be ${KEY_BYTES} bytes`);
  }
  for (const st of env.recipients) {
    let dek: Uint8Array;
    try {
      dek = sodium.crypto_box_seal_open(decodeEnvelopeBase64(st.wrapped_key, "wrapped key", WRAPPED_KEY_BYTES), pub, identity.privateKey);
    } catch {
      continue; // not sealed to us
    }
	try {
	  const aadBytes = new TextEncoder().encode(env.aad ?? "");
	  return sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
		null,
		decodeEnvelopeBase64(env.ciphertext, "ciphertext", undefined, MAX_PLAINTEXT_BYTES + TAG_BYTES),
		aadBytes,
		decodeEnvelopeBase64(env.nonce, "nonce", NONCE_BYTES),
		dek,
	  );
	} finally {
	  dek.fill(0);
	}
  }
  throw new Error("no recipient stanza decrypts with this identity");
}
