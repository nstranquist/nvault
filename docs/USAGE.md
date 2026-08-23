# Usage

This guide describes the local OSS command line. It does not describe the
managed nvault Cloud service.

## Inspect the active setup

Run these commands before a scripted operation:

```sh
nvault config path
nvault config show
nvault doctor
```

`config show` reports the selected identity, store, scope, and passphrase input
source. It does not report the private key, passphrase, or stored values.

## Manage local values

The interactive `set` command reads the value without echo:

```sh
nvault set API_TOKEN
nvault set LOG_LEVEL --kind param
nvault list
nvault get LOG_LEVEL
nvault delete LOG_LEVEL
```

Use `--scope NAME` on these commands to select a logical scope. The default is
`global`. A key, kind, and scope form the encrypted item identity. `list` emits
metadata only. `get` emits plaintext to standard output.

When standard input is not a terminal, `set` reads the value from standard
input. Use a protected pipe from the system that already owns the value. Do not
place the value in a command-line argument or a shell history entry.

## Start a child process

Pass only the values that the child needs:

```sh
nvault run --only API_TOKEN,DATABASE_URL -- your-command --your-flag
```

The key must be a valid environment-variable name. `run` adds the selected
values to the child environment and removes `NVAULT_IDENTITY_KEY` and
`NVAULT_PASSPHRASE` from it. It does not change the parent shell. The command
must follow `--`.

`--all` is available for a child that needs every value in the selected scope.
Use it only after you review that child and the scope contents.

## Use low-level envelopes

The low-level commands are for interoperability and explicit recipient flows:

```sh
nvault keygen > identity.json
printf '%s' 'value' |
  nvault encrypt --identity identity.json --aad 'org/env/global/TOKEN' > token.json
nvault decrypt --identity identity.json --aad 'org/env/global/TOKEN' < token.json
```

`keygen` writes an unprotected raw private-key backup. Protect it immediately.
For normal local use, prefer `nvault init`, which creates a passphrase-protected
identity.

The `--aad` value is part of the authenticated slot. Decryption fails when the
expected slot differs. Read [WIRE_FORMAT.md](WIRE_FORMAT.md) before another
implementation consumes these envelopes.

## Automate without prompts

Use an owner-only passphrase file or an existing secret broker:

```sh
nvault init --passphrase-file /protected/nvault-passphrase --json
nvault doctor --passphrase-file /protected/nvault-passphrase --json
```

`NVAULT_IDENTITY_KEY` and `NVAULT_PASSPHRASE` are explicit environment seams.
They are less isolated than protected files or a broker. Read
[CONFIGURATION.md](CONFIGURATION.md) for precedence and security policy.
