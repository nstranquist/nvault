# Troubleshooting

Start with read-only diagnostics:

```sh
nvault config path
nvault config show
nvault doctor
```

These commands report selected paths, setting sources, and safety failures.
They do not print secret values, a private key, or a passphrase.

## A file has unsafe permissions

On POSIX systems, nvault rejects security files that grant group or other
access. Check that you selected the intended path. Then restrict a regular file
to its owner and a store directory to its owner:

```sh
chmod 600 /exact/path/to/file
chmod 700 /exact/path/to/store
nvault doctor
```

Do not apply these commands to a path until you verify its owner and purpose.
nvault also rejects symlinks for security-sensitive files. Replace an
unexpected symlink with a reviewed regular file; do not weaken the check.

## The identity does not unlock

The error `could not unlock; check the passphrase and file` means that the
selected passphrase does not unlock the selected protected identity, or that
the file is damaged. Run `nvault config show` to verify both selected paths.

There is no reset that can decrypt the store without the correct identity and
passphrase. Restore the protected identity from its separate backup and use the
matching passphrase. Keep the current files until recovery is verified.

## Initialization says a file already exists

`nvault init` does not replace an existing configuration or identity. This is a
safety rule. Run `nvault config show` and `nvault doctor`. Continue with the
existing setup, or select new explicit paths after you preserve the old data.

## A moved envelope does not decrypt

The scope, kind, key, and explicit associated data are authenticated. An
envelope copied to another logical slot must fail to decrypt. Use the original
slot, or decrypt and encrypt the value through an authorized migration. Do not
edit the envelope JSON to bypass this check.

## A child process does not receive a value

The command form is:

```sh
nvault run --only KEY_ONE,KEY_TWO -- your-command argument
```

Use `--` before the child command. Each selected key must be a valid environment
variable name. `run` fails when neither `--only` nor explicit `--all` is set.
Run `nvault list` in the same scope to verify metadata without revealing values.

## A non-interactive command waits for input

Interactive `init`, store access, and protected identity access can request a
passphrase. For automation, set `--passphrase-file` to an owner-only file or use
an existing secret broker. Do not put the passphrase in an argument. The raw
`NVAULT_PASSPHRASE` environment seam exists for controlled automation, but
`doctor` reports it because it is less isolated.

## Configuration is rejected

The configuration parser rejects unknown fields, trailing data, unsupported
formats, oversized files, unsafe permissions, and symlinks. Correct the source
file. Do not make the parser permissive. Read [CONFIGURATION.md](CONFIGURATION.md)
for the exact format and precedence.

If these checks do not explain the failure, open a support request as described
in [SUPPORT.md](../SUPPORT.md). Remove values, private keys, passphrases, tokens,
and local paths that identify a person before you attach diagnostics.
