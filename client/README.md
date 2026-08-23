# @nvault/client

`@nvault/client` implements the `nvault.enc.v1` envelope format and the hosted
sync transport. Encryption and decryption run in the caller. The transport
sends and receives ciphertext only.

Status: `0.2.0-alpha.1`. The package is publish-ready. It is not on npm until
the package owner reserves `@nvault/client`, configures the trusted publisher,
and the release checklist records both the public package and its provenance.

## Install

```sh
pnpm add @nvault/client
```

Node.js 20 or later is required. Modern browsers are supported through a
bundler.

## Encrypt and decrypt

```ts
import {
  generateIdentity,
  openEnvelope,
  rewrapEnvelope,
  sealEnvelope,
} from "@nvault/client";

const identity = await generateIdentity();
const slot = "org_123/env_456/global/DB_URL";

const envelope = await sealEnvelope(
  new TextEncoder().encode("postgres://private"),
  [{ id: "member-owner", public_key: identity.publicKey }],
  slot,
);

const plaintext = await openEnvelope(envelope, identity, slot);

// Rotate recipients without changing the encrypted body or nonce.
const nextIdentity = await generateIdentity();
const nextRecipients = [
  { id: "member-next", public_key: nextIdentity.publicKey },
];
const rotated = await rewrapEnvelope(envelope, identity, slot, nextRecipients);
```

Always derive the expected slot from the item that the caller requested. Do
not trust the `aad` field in downloaded data. This rule prevents whole-envelope
relocation.

Use `encodePrivateKey` only for a protected offline backup. Restore it with
`identityFromPrivateKey`. The package does not store private keys for you.

## Sync ciphertext

```ts
import { NvaultClient, sealEnvelope } from "@nvault/client";

const client = new NvaultClient({
  baseUrl: "https://your-deployment.convex.site",
  org: "org_123456789",
  env: "env_123456789",
  scope: "global",
  token: process.env.NVAULT_TOKEN!,
});

// Fetch the public keys and generation needed to seal a managed write.
const policy = await client.policy();
const versions = await client.versions(["DB_URL"]);
const managedSlot = "org_123456789/env_123456789/global/DB_URL";
const managedEnvelope = await sealEnvelope(
  new TextEncoder().encode("postgres://private"),
  policy.recipients,
  managedSlot,
);
await client.push(
  [
    {
      key: "DB_URL",
      kind: "secret",
      ciphertext: JSON.stringify(managedEnvelope),
      expected_version: versions.results[0].version,
    },
  ],
  { recipientRevision: policy.recipient_revision },
);

const items = await client.pull();

// Compare-and-swap deletion. A stale version fails with HTTP 409.
await client.delete("DB_URL", items[0].version);

// For bounded-memory consumers, process one server page at a time.
const page = await client.pullPage({ limit: 10 });
```

`pull` returns live items only. Never infer a deletion from an absent key. Use
`delete` with the version from `pull` or `versions`. Every push and delete is a
compare-and-swap operation; HTTP 409 means that the caller must fetch current
state and make an explicit conflict decision.

Service tokens are bearer credentials. Keep them out of source code and logs.
The server validates envelope structure, slot binding, current recipient IDs,
and the recipient revision. It cannot decrypt the value or prove that an opaque
wrapped key opens with a specific private key. Authorized writers remain inside
the availability trust boundary.

The client requires HTTPS outside `localhost`, `127.0.0.1`, and `::1`. A private
development network can set `allowInsecureHttp: true` explicitly. Do not use
that option for an internet endpoint.

## Limits

- local envelope plaintext: 16 MiB;
- hosted item plaintext before encryption: 256 KiB;
- recipients: 1 to 1,024;
- associated data: 4,096 UTF-8 bytes;
- recipient ID: 256 UTF-8 bytes;
- push batch: 100 items;
- version query: 100 keys;
- pull response: 10 items per cursor page.

Malformed or oversized envelopes fail before a cryptographic operation runs.

## Verify

```sh
corepack pnpm@11.15.1 install --frozen-lockfile
corepack pnpm@11.15.1 test
corepack pnpm@11.15.1 audit --prod
```

The tests build the Go CLI and prove Go-to-TypeScript and TypeScript-to-Go
interoperability. The generated types come from `cmd/nvault-schemagen` in the
repository root.

Apache-2.0. See `LICENSE` in this package.
