# nvault

nvault is a local, zero-knowledge secrets engine. It encrypts each value for one
or more X25519 recipients and binds the ciphertext to its logical slot. A moved
or modified envelope does not decrypt.

This repository is the Apache-2.0 OSS core. It contains:

- the Go `nvault.enc.v1` implementation;
- a passphrase-protected local store and process-injection CLI;
- strict user configuration, an interactive first-run wizard, and a safety doctor;
- the `@nvault/client` TypeScript SDK, including body-preserving recipient
  re-wrap and a versioned ciphertext transport;
- Go-to-TypeScript schema generation and cross-language tests.

The managed multi-tenant service, dashboard, billing, and operations code are
not part of this repository. The OSS core does not include a self-hosted clone
of nvault Cloud. See [OSS_BOUNDARY.md](docs/OSS_BOUNDARY.md).

## Status

Version [`v0.2.0-alpha.1`](https://github.com/nstranquist/nvault/releases/tag/v0.2.0-alpha.1)
is the first public alpha release. The source is at
[github.com/nstranquist/nvault](https://github.com/nstranquist/nvault). Use the
[GitHub releases](https://github.com/nstranquist/nvault/releases) page as the
authoritative record for tagged CLI releases and checksums. A checkout alone is
not proof of a public release.

The `@nvault/client` package is publish-ready, but it is not on npm. Its
first publish needs the package owner to reserve the package and configure npm
trusted publishing for `.github/workflows/npm-publish.yml`. The CLI release is
independent from that human account gate.

## Build from this checkout

Requirements: Go 1.26, Node.js 20 or later, and Corepack. The repository pins
pnpm 11.15.1.

```sh
go build -trimpath -o nvault ./cmd/nvault
corepack pnpm@11.15.1 --dir client install --frozen-lockfile
make verify
```

After the first tagged release, users can install the CLI with:

```sh
go install github.com/nstranquist/nvault/cmd/nvault@latest
```

## Local quick start

For an interactive first run, build the CLI and run:

```sh
./nvault init
./nvault doctor
```

The wizard shows the resolved paths and reads the passphrase without echoing it.
It writes a strict `nvault.config.v1` file. Back up the protected identity file
separately from the encrypted store.

Normal commands fail closed on group-readable or other-readable security files
on POSIX systems. Run `nvault doctor` after moving a backup or changing paths.

For a file-backed setup, create an owner-only passphrase file with a protected
editor or an existing secret manager. Keep it separate from the identity
backup. Do not put the passphrase or a secret in a command-line argument or
shell history.

```sh
umask 077
install -m 600 /dev/null ./nvault-passphrase
${EDITOR:?Set EDITOR to a protected local editor} ./nvault-passphrase

./nvault init --passphrase-file ./nvault-passphrase
./nvault set DB_URL

./nvault list
./nvault get DB_URL
./nvault run --only DB_URL -- your-command
```

`run` adds selected values only to the child process. It does not modify the
parent shell. It removes nvault's raw identity and passphrase environment values
before it starts the child. Use `--all` only when the child needs every value in
the scope. `list` returns metadata only. It never returns secret values.

Defaults:

- configuration: `$NVAULT_CONFIG_FILE`, or the user configuration directory;
- identity: `$NVAULT_IDENTITY_FILE`, or the user configuration directory;
- store: `$NVAULT_STORE_DIR`, or the user configuration directory;
- passphrase: `--passphrase-file`, `$NVAULT_PASSPHRASE_FILE`, or
  `$NVAULT_PASSPHRASE`;
- scope: `$NVAULT_SCOPE`, or `global`.

The precedence is command-line flag, environment variable, configuration file,
then built-in default. There is no implicit repository configuration because a
cloned repository must not be able to redirect identity or passphrase paths.
See [CONFIGURATION.md](docs/CONFIGURATION.md).

For automation, inject an `nvpriv_...` value through `NVAULT_IDENTITY_KEY` from
an existing secret manager. Avoid a raw identity file when a protected identity
or external secret provider is available.

## Usage

Use `set`, `get`, `list`, and `delete` to manage one local encrypted store. Use
`--scope` to keep independent logical groups. Use `run --only` to send the
smallest required set of values to one child process.

```sh
./nvault set API_TOKEN
./nvault list
./nvault get API_TOKEN
./nvault run --only API_TOKEN -- your-command --your-flag
./nvault delete API_TOKEN
```

`set` reads a value without echo when standard input is a terminal. `get` writes
plaintext to standard output, so do not send it to logs. `run` requires an
explicit `--only KEY,...` list or `--all`; prefer `--only`.

Read [USAGE.md](docs/USAGE.md) for the complete command map and safe automation
examples.

## Envelope CLI

The low-level commands read plaintext or envelope JSON from standard input.

```sh
./nvault keygen > identity.json
printf '%s' 'value' |
  ./nvault encrypt --identity identity.json --aad 'org/env/global/TOKEN' > token.json
./nvault decrypt --identity identity.json --aad 'org/env/global/TOKEN' < token.json
```

`keygen` writes a raw private-key backup. Protect that output. The higher-level
`init` command creates an Argon2id and AES-256-GCM protected identity instead.

## Security model

Each value uses a random 256-bit data-encryption key and
XChaCha20-Poly1305. The data key is wrapped to each X25519 recipient with an
anonymous sealed box. Associated data binds the envelope to a caller-supplied
slot. Decryption requires both the correct identity and the expected slot.

The local identity file uses Argon2id with a unique salt and AES-256-GCM. The
current Argon2id work factors are recorded in the file and fixed for format v1.

Read [THREAT_MODEL.md](docs/THREAT_MODEL.md) before production use and
[WIRE_FORMAT.md](docs/WIRE_FORMAT.md) before implementing another client.

## Architecture

The CLI resolves strict user configuration, unlocks one protected identity,
and reads or writes an encrypted local store. The `crypto` package owns the
envelope construction. The TypeScript client implements the same wire contract
for managed ciphertext transport, but the managed server is not in this
repository.

Read [ARCHITECTURE.md](docs/ARCHITECTURE.md) for component ownership, data flows,
trust boundaries, and the Go-to-TypeScript compatibility gate.

## Troubleshooting

Run `./nvault doctor` first. Then run `./nvault config show` to see the selected
paths and the source of each setting. These commands do not print a secret,
private key, or passphrase.

Do not bypass permission, symlink, passphrase, or slot-binding errors. Correct
the selected file or setting, then run `doctor` again. Read
[TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md) for exact checks and safe repairs.

## Verify

```sh
make verify
make publish-ready
```

The gates run Go race tests and vet, generated-schema drift checks, TypeScript
build and Go/TypeScript interoperability tests, dependency audit, and package
contents inspection.

## Contributing and security

See [CONTRIBUTING.md](CONTRIBUTING.md), [SECURITY.md](SECURITY.md),
[SUPPORT.md](SUPPORT.md), [MAINTAINERS.md](MAINTAINERS.md), and
[CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).

## License

Apache License 2.0. See [LICENSE](LICENSE).
