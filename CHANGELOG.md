# Changelog

This project follows Semantic Versioning. Pre-release versions can change before
`1.0.0`.

## 0.2.0-alpha.1 - 2026-08-20

### Added

- passphrase-protected local identities with Argon2id and AES-256-GCM;
- atomic encrypted local store;
- `init`, `set`, `get`, `list`, `delete`, and `run` CLI commands;
- strict user configuration, a hidden-passphrase init wizard, and `doctor`;
- a canonical Go and TypeScript cloud-slot helper;
- OSS support, maintainer, issue, and pull-request guidance;
- expected-AAD checks in Go and TypeScript;
- standalone Go-to-TypeScript schema generator;
- input limits, malformed-envelope checks, and fuzz coverage;
- cross-language relocation and private-key-backup tests;
- OSS policy, threat-model, wire-format, CI, and release documentation.
- deterministic cross-platform release archives, checksums, version agreement,
  npm provenance selection, and package-content gates;
- Go crypto and durable-store benchmark baselines.

### Security

- decryption rejects whole-envelope relocation;
- rewrap authenticates the unchanged ciphertext before it changes recipients;
- malformed nonce and stanza lengths return errors instead of panicking;
- duplicate recipient IDs and zero public keys are rejected;
- `run` requires an explicit secret selection and removes nvault master-key
  environment values before it starts the child process;
- local listing rejects non-regular, oversized, unknown-field, and trailing
  records before it returns metadata;
- configuration, identity, passphrase, store, and item reads reject unsafe
  POSIX modes and symlinked security files;
- the raw identity environment seam follows documented precedence and is
  reported without exposing the key.
- strict JSON readers reject duplicate fields, excessive nesting, unknown
  fields, and trailing data across envelopes, identities, configuration, wire
  records, and local items;
- public and private keys require canonical encodings and reject all-zero key
  material;
- sensitive temporary buffers are cleared where the language permits;
- verified directory handles prevent path replacement and symlink traversal
  during security-file access and atomic item replacement.

## 0.1.0 - private extract

Initial envelope-crypto extraction. This version was not published.
