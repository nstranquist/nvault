# Contributing

Thank you for improving nvault.

## Before you change code

1. Open an issue for a wire-format or cryptographic change.
2. Read `docs/THREAT_MODEL.md` and `docs/WIRE_FORMAT.md`.
3. Do not place real credentials in tests, examples, issues, or commits.

## Development

Use Go 1.26, Node.js 20 or later, and Corepack. The repository pins pnpm
11.15.1 so local and release gates use the same package manager.

```sh
corepack pnpm@11.15.1 --dir client install --frozen-lockfile
make publish-ready
```

The command runs race tests, `go vet`, pinned static analysis, vulnerability
and secret scans, cross-language tests, the schema drift check, the production
dependency audit, and a dry-run package build. The first run downloads the
pinned analysis tools into the Go module cache.

Add tests for success, tampering, wrong-slot use, malformed input, and resource
bounds when they apply. Run the Go-to-TypeScript compatibility suite for every
wire change.

Read [CONFIGURATION.md](docs/CONFIGURATION.md) before adding a configuration
source. Do not add implicit repository configuration that can redirect identity
or passphrase paths.

Generate TypeScript types with:

```sh
go run ./cmd/nvault-schemagen client/src/types.generated.ts
```

Do not edit the generated file by hand.

## Pull requests

Keep one coherent change in each pull request. Explain the threat or user
journey that changes. List the commands that you ran. State any compatibility
or migration effect.

The project uses Apache-2.0. By submitting a contribution, you agree that your
contribution is licensed under the same terms.
