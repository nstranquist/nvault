# Release procedure

Releases use Semantic Versioning. Alpha and beta identifiers are required until
the compatibility and security policies are stable.

## Prepare

1. Update `CHANGELOG.md`, the CLI version, the client version, and the Makefile
   version together.
2. Run `make publish-ready` from a clean checkout.
3. Build a temporary CLI and complete the non-interactive adopter journey:
   `init`, `config show`, `doctor`, `set`, `list`, `get`, and `run --only`.
   Confirm that list and receipts contain no secret value.
4. Review `pnpm --dir client pack --dry-run`. Confirm that it contains only
   `dist`, `README.md`, `LICENSE`, and package metadata.
5. Confirm that the public repository has private vulnerability reporting,
   branch protection, tag protection, and required CI checks.
6. Confirm that `.github/workflows/npm-publish.yml` is the trusted publisher
   for `@nvault/client`. Bind it to the `npm-release` GitHub environment. Do not
   add a long-lived npm token.
7. Review both release workflows. A pushed `vX.Y.Z` tag publishes CLI archives,
   SHA-256 checksums, and a GitHub release. npm publication is a separate manual
   action, so an unavailable npm account cannot make the CLI release partial.

## Publish

The repository owner must perform the first public release. Do not create a
remote, change visibility, push a tag, create a GitHub release, or publish to npm
without explicit approval.

1. Create and push an annotated `vX.Y.Z` tag from a clean, reviewed commit. The
   tag version must match the CLI, Makefile, changelog, and npm package.
2. Let the tag-triggered release workflow build CLI archives and SHA-256
   checksums from that exact tag and create the GitHub release.
3. Verify the public clone, `go install`, binary version, and checksums from a
   clean external directory.
4. Record the CLI URLs and immutable digests in the release receipt.
5. Reserve `@nvault/client` in the npm account. Configure its trusted publisher
   for repository `nstranquist/nvault`, workflow `npm-publish.yml`, and GitHub
   environment `npm-release`.
6. Manually run `Publish npm client` with the existing release tag. The workflow
   checks out that tag, verifies the GitHub release, selects `next` for a
   prerelease, and publishes with an OIDC identity and provenance.
7. Verify npm installation and provenance from a clean external directory.
   Add the package URL and integrity value to the release receipt.

The release is public only after the external verification succeeds.
