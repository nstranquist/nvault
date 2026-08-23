# OSS core boundary

## Apache-2.0 repository

This repository contains the reusable security engine:

- envelope encryption and rewrap;
- local identity protection and encrypted storage;
- strict user configuration, first-run wizard, doctor, local CLI, and process
  injection;
- TypeScript crypto, canonical cloud-slot, and sync transport contracts;
- schema generation, tests, and documentation.

Users can build, modify, redistribute, and embed this code under Apache-2.0.

## Managed product boundary

nvault Cloud is a separate managed product. Its multi-tenant storage, browser
dashboard, identity provider setup, billing, deployment configuration, and
operational telemetry are not distributed from this repository.

The `NvaultClient` transport is public so an OSS client can speak to the hosted
ciphertext API. A public client contract does not make the managed server part
of the OSS core.

The repository does not contain hosted authentication, tenant persistence,
billing, the browser dashboard, email delivery, deployment configuration, or
service operations. Contributors must not add a server dependency to the local
encryption and storage path.

## Self-hosting language

The OSS core runs on infrastructure that the user controls as a local CLI or an
embedded library. It does not include a self-hosted replacement for nvault
Cloud. Product pages must not claim full cloud self-hosting unless a separately
licensed and supported server exists.

## Compatibility policy

The `nvault.enc.v1` wire contract is public. The managed service must accept the
same valid envelopes and must not require a server-held decryption key. Breaking
wire changes require a new format tag and an explicit migration plan.

The canonical cloud slot is `org/environment/scope/key`. Each segment is
validated before it becomes associated data. Go and TypeScript compatibility
tests must pass before a managed service adopts a new client version.
