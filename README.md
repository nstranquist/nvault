# nvault

Extracted zero-knowledge envelope core for [nvault](https://nvault.nicos.tools/landing.html).

This tree is the **publishable engine**: `nvault.enc.v1` (X25519 wrap +
XChaCha20-Poly1305) plus a tiny CLI and the TypeScript client. It is **not
public** yet. Do not add a GitHub remote or flip visibility.

## What lives here

| Path | Role |
|---|---|
| `crypto/` | Go envelope implementation (source of truth for the wire format) |
| `cmd/nvault` | `keygen` / `encrypt` / `decrypt` against that format |
| `client/` | `@nvault/client` TypeScript SDK (byte-parity with Go) |

## What stays in nicos-tools

- `ndev vault` / `nvault` operator CLI (Keychain, scopes, `run --only`)
- `run --managed` provenance broker
- Convex cloud, Stripe, dashboard (`apps/nvault-cloud`)
- Factory catalog, Keyring consumer app

## Operator inject path (today)

```sh
ndev vault run --only PRODUCTHUNT_API_TOKEN,GITHUB_TOKEN --passthrough HOME \
  -- ngtm feeds browse --json --cache --hydrate
```

Do not `ndev secrets export` into the parent shell for this.

## Develop

```sh
go test ./...
go run ./cmd/nvault version
```

## Status

Private extract. Public launch waits on `apps/nvault-cloud` go-live
(`scripts/go-live-check.sh`) so the hosted product and the open engine
ship in the same week.
