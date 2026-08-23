# Configuration

nvault uses one optional user configuration file. The file contains paths and a
default scope. It never contains a passphrase, private key, token, or secret
value.

Run these commands to inspect the active settings:

```sh
nvault config path
nvault config show
nvault doctor
```

## First-run wizard

Run `nvault init` in a terminal. The command reads and confirms a hidden
passphrase. It then creates:

- an owner-only `nvault.config.v1` configuration file;
- an Argon2id and AES-256-GCM protected identity file;
- an owner-only encrypted store directory.

Use `--identity`, `--store`, `--scope`, or `--config` to select other paths and
defaults. Use `--no-config` only when you want built-in defaults and environment
variables without a configuration file.

For automation, use `--passphrase-file FILE` or
`NVAULT_PASSPHRASE_FILE=FILE`. `init --json` returns a machine-readable receipt.

## File format

```json
{
  "format": "nvault.config.v1",
  "identity_file": "/home/me/.config/nvault/identity.json",
  "store_dir": "/home/me/.config/nvault/store",
  "passphrase_file": "/secure/path/nvault-passphrase",
  "default_scope": "global"
}
```

`passphrase_file` is a path. It is not the passphrase. Relative paths are
resolved from the directory that contains the configuration file. Unknown
fields, trailing JSON data, unsupported formats, and oversized files fail
closed.

On POSIX systems, normal commands also reject a configuration, identity,
passphrase, store directory, or item file that grants group or other access.
Symlinks are not accepted for these security-sensitive files.

## Precedence

The highest-precedence value wins:

1. command-line flag;
2. environment variable;
3. configuration file;
4. built-in default.

The supported environment variables are:

- `NVAULT_CONFIG_FILE`;
- `NVAULT_IDENTITY_FILE`;
- `NVAULT_STORE_DIR`;
- `NVAULT_PASSPHRASE_FILE`;
- `NVAULT_SCOPE`.

`NVAULT_PASSPHRASE` and `NVAULT_IDENTITY_KEY` are explicit automation seams.
They place key material in the process environment. Prefer protected files or
an existing secret broker. `nvault run` removes these two values before it
starts the child process.

`NVAULT_IDENTITY_KEY` selects a raw process-environment identity instead of the
configured identity file. An explicit `--identity` flag has higher precedence.
`nvault config show` reports the winning source for the identity, store,
passphrase input, and scope. It does not show a key or passphrase. `nvault
doctor` warns when the raw environment seam is active.

Cryptographic work factors, input bounds, and file-permission policy are not
configuration options. They are versioned security policy. A future change to
them requires a format and migration review, not an unreviewed local setting.

## Repository configuration

nvault does not load a configuration file from the current repository. This is
a security boundary: an untrusted clone cannot redirect the CLI to an attacker
selected identity, store, or passphrase file. A project can select a logical
scope in its documented command or task runner. A user must explicitly select
any non-default configuration with `--config` or `NVAULT_CONFIG_FILE`.
