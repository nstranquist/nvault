# `nvault.enc.v1` wire format

An envelope is one JSON object:

```json
{
  "v": "nvault.enc.v1",
  "alg": "x25519-xchacha20poly1305",
  "nonce": "base64-standard",
  "ciphertext": "base64-standard",
  "recipients": [
    {
      "recipient_id": "member-owner",
      "wrapped_key": "base64-standard"
    }
  ],
  "aad": "org/environment/scope/KEY"
}
```

## Encryption

1. Generate a random 32-byte data-encryption key.
2. Generate a random 24-byte XChaCha20-Poly1305 nonce.
3. Encrypt the plaintext with the data key, nonce, and UTF-8 associated data.
4. Wrap the data key to each recipient's 32-byte X25519 public key with a NaCl
   anonymous sealed box.
5. Sort recipient stanzas by recipient ID.

The encrypted body includes the 16-byte Poly1305 tag. Each wrapped key is 80
bytes. JSON uses padded standard base64 for binary envelope fields. Public and
private key strings use unpadded URL-safe base64 with the `nvpub_` and `nvpriv_`
prefixes.

## Decryption contract

The caller must provide `expectedAAD` from the requested logical slot. The
reader compares it with the envelope field before it attempts decryption. A
reader must not copy the expected value from the untrusted envelope.

Unknown versions or algorithms must fail closed. A v1 reader must not guess how
to process a future format.

## Limits

- plaintext: 16 MiB;
- envelope JSON: 32 MiB;
- recipients: 1 to 1,024;
- recipient ID: 1 to 256 bytes;
- associated data: 4,096 bytes;
- nonce: exactly 24 bytes;
- wrapped key: exactly 80 bytes;
- ciphertext: 16 bytes to 16 MiB plus 16 bytes.

Implementations must validate these limits before a cryptographic primitive
runs.

## Compatibility gate

`client/test/crosslang.test.mjs` proves encryption and decryption in both
directions between Go and TypeScript. `cmd/nvault-schemagen` owns the generated
TypeScript declarations. A wire change is incomplete until these gates pass.
