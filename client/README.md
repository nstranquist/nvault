# @nvault/client

Typed TypeScript SDK for the **nvault** zero-knowledge secrets + parameter
platform. Two layers:

- **Transport** (`NvaultClient`) — talks to the nvault-cloud `/sync` HTTP API
  with a service token. Uploads/downloads **ciphertext only**.
- **Crypto** (`sealEnvelope` / `openEnvelope`) — client-side E2EE that is
  byte-compatible with the Go reference (`nicos-dev/internal/vault/crypto`).

## Type parity (no drift)

`src/types.generated.ts` is generated from the Go source by `nvault-schemagen`:

```bash
go run ./nicos-dev/cmd/nvault-schemagen packages/nvault-client/src/types.generated.ts
# CI parity check:
go run ./nicos-dev/cmd/nvault-schemagen --check packages/nvault-client/src/types.generated.ts
```

The generator reads the live Go constants (`vault.Kind`, `vault.ValueType`,
`crypto.FormatV1`/`AlgV1`), so a change in Go fails the `--check` until the TS is
regenerated. This is the same pattern as `nvr-schemagen` /
`scratchpad-schemagen`.

## Usage

```ts
import {
  NvaultClient,
  generateIdentity,
  sealEnvelope,
  openEnvelope,
} from "@nvault/client";

const me = await generateIdentity(); // X25519 keypair; keep me.privateKey secret
const client = new NvaultClient({
  baseUrl: "https://<deployment>.convex.site",
  org: "org_…",
  env: "env_…",
  token: process.env.NVAULT_TOKEN!,
});

// push (seal client-side, upload ciphertext)
const env = await sealEnvelope(
  new TextEncoder().encode("super-secret"),
  [{ id: me.publicKey, public_key: me.publicKey }],
  "org_…/env_…/global/DB_URL",
);
await client.push([{ key: "DB_URL", kind: "secret", ciphertext: JSON.stringify(env) }]);

// pull (download ciphertext, open locally)
const { 0: first } = await client.pull();
const plain = await openEnvelope(JSON.parse(first.ciphertext), me);
```

## Build

```bash
pnpm install
pnpm build       # tsc → dist/
pnpm typecheck
```

Requires `libsodium-wrappers` (sealed box, NaCl-compatible) and
`@noble/ciphers` (XChaCha20-Poly1305). The transport layer (`./client`) has no
crypto dependency and can be used standalone.
