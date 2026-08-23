# Security policy

## Supported versions

`0.2.0-alpha.1` is a pre-release. Security fixes apply to the newest published
version only. No version is public until a GitHub release exists.

## Report a vulnerability

Do not open a public issue for a suspected vulnerability.

After the repository is public, use GitHub's private vulnerability-reporting
form. Include the affected version, a minimal reproduction, the expected impact,
and any suggested mitigation. Do not include real credentials or third-party
data.

Before publication, report the issue directly to the repository owner through
an existing private channel. The public-launch checklist requires private
vulnerability reporting to be enabled before the repository is announced.

## Response targets

- acknowledge a complete report within three business days;
- confirm severity and next steps within seven business days;
- coordinate disclosure after a fix is available.

These targets are goals, not a service-level agreement.

## Scope

In scope:

- envelope authentication, recipient wrapping, and key parsing;
- identity-file protection and local-store isolation;
- plaintext exposure through the CLI or TypeScript client;
- denial-of-service paths that bypass documented bounds;
- Go and TypeScript interoperability defects that weaken authentication.

The managed nvault Cloud service has a separate security boundary and is not
licensed or distributed from this repository.
