# Chocolatey package source — NOT PUSHED (GV4-gated)

Seeded by Phase P2 Track Release-eng (C2) from the DIST-002 research drafts in
`apiarylens-ops` (`design/research/2026-07-18-dist-002-chocolatey-spike.md`).

- **Pushing to the Chocolatey Community Repository is locked until GV4**
  (signed stable artifacts + owner approval). Stable versions only; previews
  and RCs are never submitted.
- The `chocolatey-submission` job in `.github/workflows/release.yml` is
  hard-gated with `if: false` and a `# GV4 gate:` comment.
- `{VERSION}` and `{SHA256_EXE_AMD64}` are placeholders substituted by the
  release workflow from the published release `SHA256SUMS` at pack time.
- Automation is first-party `choco pack` + `choco push` only. chocolatey-AU is
  deliberately **not** used: it is GPL-2.0 and exists for third-party
  maintainers scraping vendor sites, neither of which applies here.

Shape: portable package. The exe is downloaded at install time from the
official GitHub release asset (checksum-verified), landed in `tools/` as
`scout-bee.exe`, and shimmed onto PATH as `scout-bee` by shimgen. When
installed through Chocolatey, Scout Bee's own self-update is suppressed via
the package-manager marker; `choco upgrade scout-bee` is the update path.
