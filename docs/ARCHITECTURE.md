# Architecture

nvault is a local encrypted-store core with one cross-language envelope
contract. The managed multi-tenant service is a separate proprietary product.

## Components

- `cmd/nvault` owns command parsing, terminal prompts, configuration selection,
  and child-process injection.
- `config` owns the strict, non-secret `nvault.config.v1` file and setting
  precedence.
- `identity` owns the Argon2id and AES-256-GCM protected local identity file.
- `crypto` owns X25519 recipients, XChaCha20-Poly1305 value encryption, wrapped
  data keys, input bounds, and authenticated slot data.
- `store` owns the local encrypted item files, metadata listing, and atomic file
  replacement.
- `wire` owns strict envelope decoding and the shared wire constraints.
- `cmd/nvault-schemagen` generates the TypeScript wire types from the Go source
  contract.
- `client` is the TypeScript envelope and ciphertext-transport SDK. It does not
  contain a managed server.

## Local write flow

1. The CLI resolves flags, environment variables, the user configuration file,
   and built-in defaults in that order.
2. It validates the selected paths, file types, ownership permissions, and
   symlink policy.
3. It unlocks the protected identity with a passphrase from a terminal,
   owner-only file, or explicit automation seam.
4. It binds the scope, kind, and key into the authenticated slot.
5. The crypto package encrypts the value with a random data key and wraps that
   key to the selected X25519 recipients.
6. The store writes the envelope through an atomic replacement. It does not
   write the plaintext value.

## Local read and run flow

`list` reads metadata without decrypting a value. `get` loads one envelope,
checks the expected slot, unwraps the data key, and writes plaintext to standard
output.

`run` performs the same read for an explicit key set. It adds those values only
to a child environment, removes nvault's raw identity and passphrase environment
seams, starts the child, and leaves the parent environment unchanged.

## Trust boundaries

The protected identity, its passphrase, the encrypted store, and the child
process are separate assets. A store copy is not useful without an authorized
identity. A protected identity copy is not useful without its passphrase. A
compromised unlocked process can still read values that process is authorized
to use.

Associated data prevents an attacker from moving a valid envelope to another
scope, kind, or key without detection. It does not hide metadata such as an item
name. Read [THREAT_MODEL.md](THREAT_MODEL.md) for the complete threat boundary.

## Cross-language compatibility

Go is the wire-schema authority. The schema generator checks the committed
TypeScript types. Cross-language tests cover Go-to-TypeScript decryption,
TypeScript-to-Go decryption, canonical encodings, strict JSON, relocation
failure, wrong keys, recipient re-wrap, and the managed ciphertext slot.

The managed client source is checked for exact parity with the public client.
The proprietary service can store and authorize ciphertext, but the OSS
repository does not claim that the service is self-hostable. Read
[OSS_BOUNDARY.md](OSS_BOUNDARY.md) and [WIRE_FORMAT.md](WIRE_FORMAT.md) for those
contracts.
