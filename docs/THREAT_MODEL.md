# Threat model

## Security objective

nvault keeps a value confidential and authentic when an attacker obtains the
encrypted store or controls an untrusted ciphertext transport. The caller must
keep the identity private key and passphrase secret.

## Assets

- plaintext values;
- identity private keys and recovery backups;
- the identity-file passphrase;
- recipient membership and logical slot names.

Slot names and recipient IDs are metadata. They are authenticated, but they are
not encrypted.

## Trust boundaries

The Go or TypeScript process that holds a decrypted identity is trusted. The
encrypted store, sync server, network, and envelope JSON are untrusted. The
operating system and process environment are outside the cryptographic boundary.

## Defenses

- XChaCha20-Poly1305 authenticates ciphertext and associated data.
- A fresh random data-encryption key is used for each envelope.
- X25519 sealed boxes wrap that key for each recipient.
- The caller supplies the expected associated data during decryption.
- The local store derives associated data from `scope` and `key`.
- Envelope and JSON sizes, recipient counts, and field lengths are bounded.
- Local files use owner-only permissions and atomic replacement.
- Normal reads reject symlinked or group/other-accessible security files on
  POSIX systems; `doctor` reports the resolved configuration and store state.
- Identity files use Argon2id, a unique salt, and AES-256-GCM.
- `run` requires `--only` or explicit `--all`, gives values only to one child,
  and removes nvault's raw identity and passphrase environment values first.

## Attacks that should fail

- change a nonce, ciphertext, stanza, or associated-data field;
- move a valid envelope to another key or scope;
- decrypt with a non-recipient identity;
- publish a rewrap of a corrupted ciphertext body;
- use duplicate recipient IDs to create ambiguous policy;
- use oversized data to force unbounded parsing or cryptographic work.

## Not protected

nvault does not protect a value after a trusted process decrypts it. Malware,
debuggers, browser extensions, shell tracing, crash dumps, and a compromised
operating system can read process memory or environment variables.

The local store does not hide keys, scopes, update times, recipient IDs, or
ciphertext sizes. It does not provide rollback detection against an attacker who
can replace the complete store with an older valid copy.

A weak passphrase can be guessed offline from a stolen identity file. Use a
long, unique passphrase. Keep the passphrase file separate from the identity
file and encrypted store.

`NVAULT_IDENTITY_KEY` and `NVAULT_PASSPHRASE` are automation seams. A process
with permission to inspect the parent environment can read them. Prefer a
protected passphrase file or an existing secret broker when one is available.
`nvault run` removes both from the child environment unless the user explicitly
stores and selects a value with the same name.

The OSS core is not a self-hosted multi-user service. It does not provide remote
authentication, RBAC, billing, or hosted audit storage.

## Cryptographic review status

The implementation uses standard primitives from Go's extended standard
library and libsodium. The composition has automated interoperability and
tamper tests. It has not received an independent professional cryptographic
audit. Treat the alpha version accordingly.
