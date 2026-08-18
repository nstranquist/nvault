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

export interface Identity {
  /** nvpub_… encoded public key */
  publicKey: string;
  /** raw 32-byte X25519 private key */
  privateKey: Uint8Array;
}

const PUB_PREFIX = "nvpub_";

function b64(b: Uint8Array): string {
  return sodium.to_base64(b, sodium.base64_variants.ORIGINAL);
}
function unb64(s: string): Uint8Array {
  return sodium.from_base64(s, sodium.base64_variants.ORIGINAL);
}

/** Decode the nvpub_… form (base64url, no padding) to raw 32 bytes. */
export function decodePublicKey(s: string): Uint8Array {
  if (!s.startsWith(PUB_PREFIX)) throw new Error(`public key must start with ${PUB_PREFIX}`);
  const raw = sodium.from_base64(s.slice(PUB_PREFIX.length), sodium.base64_variants.URLSAFE_NO_PADDING);
  if (raw.length !== 32) throw new Error(`public key must be 32 bytes, got ${raw.length}`);
  return raw;
}

/** Encode raw 32 bytes to the nvpub_… form. */
export function encodePublicKey(raw: Uint8Array): string {
  return PUB_PREFIX + sodium.to_base64(raw, sodium.base64_variants.URLSAFE_NO_PADDING);
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
  if (recipients.length === 0) throw new Error("at least one recipient is required");
  const dek = sodium.randombytes_buf(sodium.crypto_aead_xchacha20poly1305_ietf_KEYBYTES);
  const nonce = sodium.randombytes_buf(sodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
  const aadBytes = new TextEncoder().encode(aad);
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
    .sort((a, b) => (a.recipient_id < b.recipient_id ? -1 : 1));

  return {
    v: ENVELOPE_FORMAT_V1,
    alg: ENVELOPE_ALG_V1,
    nonce: b64(nonce),
    ciphertext: b64(ciphertext),
    recipients: stanzas,
    ...(aad ? { aad } : {}),
  };
}

/** openEnvelope decrypts an Envelope with the given identity. */
export async function openEnvelope(env: Envelope, identity: Identity): Promise<Uint8Array> {
  await sodium.ready;
  if (env.v !== ENVELOPE_FORMAT_V1 || env.alg !== ENVELOPE_ALG_V1) {
    throw new Error(`unsupported envelope format ${env.v}/${env.alg}`);
  }
  const pub = decodePublicKey(identity.publicKey);
  for (const st of env.recipients) {
    let dek: Uint8Array;
    try {
      dek = sodium.crypto_box_seal_open(unb64(st.wrapped_key), pub, identity.privateKey);
    } catch {
      continue; // not sealed to us
    }
    const aadBytes = new TextEncoder().encode(env.aad ?? "");
    return sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
      null,
      unb64(env.ciphertext),
      aadBytes,
      unb64(env.nonce),
      dek,
    );
  }
  throw new Error("no recipient stanza decrypts with this identity");
}
