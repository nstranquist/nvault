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
6. Confirm that the npm package uses trusted publishing with a GitHub-hosted
   workflow and no long-lived publish token.
7. Review the release workflow. A pushed `vX.Y.Z` tag publishes CLI archives,
   SHA-256 checksums, a GitHub release, and the matching npm package. Configure
   the repository and npm trusted publisher before the first tag.

## Publish

The repository owner must perform the first public release. Do not create a
remote, change visibility, push a tag, create a GitHub release, or publish to npm
without explicit approval.

1. Create and push an annotated `vX.Y.Z` tag from a clean, reviewed commit. The
   tag version must match the CLI, Makefile, changelog, and npm package.
2. Let the tag-triggered release workflow build CLI archives and SHA-256
   checksums from that exact tag.
3. Let the workflow create the GitHub release and publish `client/` through npm
   trusted publishing with provenance.
4. Verify the public clone, `go install`, npm install, checksum, and provenance
   from a clean external directory.
5. Record public URLs and immutable digests in the release receipt.

The release is public only after the external verification succeeds.
