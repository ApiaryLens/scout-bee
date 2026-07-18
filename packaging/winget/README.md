# winget manifests — NOT SUBMITTED (GV4-gated)

Seeded by Phase P2 Track Release-eng (C2) from the DIST-001 research drafts in
`apiarylens-ops` (`design/research/2026-07-18-dist-001-winget-spike.md`).

- **Submission to `microsoft/winget-pkgs` is locked until GV4** (signed stable
  artifacts + conformance evidence). Only stable releases are ever submitted;
  previews and RCs stay on direct download + Scout.
- The `winget-submission` job in `.github/workflows/release.yml` is hard-gated
  with `if: false` and a `# GV4 gate:` comment; it cannot run until a
  maintainer deliberately edits the workflow after the owner passes GV4.
- All versions, URLs, SHA-256 hashes, and dates in these manifests are
  **placeholders**; the komac automation rewrites `PackageVersion`,
  `InstallerUrl`, `InstallerSha256`, and `ReleaseDate` from the actual GitHub
  release at submission time.
- The **first** version of `ApiaryLens.ScoutBee` must be submitted as a manual
  PR to `microsoft/winget-pkgs` — komac can only update an existing package.

Shape (schema 1.12.0): `InstallerType: portable` with `Commands: scout-bee`.
winget owns the install directory, the PATH alias, and the ARP entry, so
version detection is exact and `winget upgrade --all` is safe without
`RequireExplicitUpgrade`. Scout Bee detects a winget-owned install by its own
executable path (under the WinGet `Packages` root), disables self-update, and
delegates to `winget upgrade ApiaryLens.ScoutBee` (DIST-001 finding 5 /
ADR 0024 input).
