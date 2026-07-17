# Scout Bee release procedure

Scout Bee versions and tags are independent from ApiaryLens product versions. A
release tag is `v<scoutVersion>` and must match `VERSION`, `package.json`, and
`compatibility.json` exactly.

The release workflow:

1. builds the embedded interface from locked dependencies;
2. runs Go and UI verification;
3. builds a portable Windows AMD64 executable and Linux AMD64 executable;
4. applies the channel-aware Windows signing policy and normally
   Authenticode-signs and timestamps the Windows executable;
5. packages the Linux executable with a concise release README;
6. creates SHA-256 and compatibility metadata;
7. creates repository-bound GitHub attestations; and
8. uploads immutable files to the matching GitHub Release.

The certificate and password are repository secrets named
`WINDOWS_SIGNING_CERTIFICATE_BASE64` and `WINDOWS_SIGNING_CERTIFICATE_PASSWORD`.
They must never be written to source, logs, manifests, diagnostics, or artifacts.

## Signing policy

Stable and RC releases are fail-closed: both signing secrets must be present, the
Windows executable must be Authenticode-signed and timestamped, and `signtool
verify /pa /all` must succeed. The workflow cannot publish an unsigned Stable or
RC package.

A Preview may be published without Authenticode only as an explicit exception:

1. create and push the immutable Preview tag normally;
2. run **Scout Bee release** manually against that exact tag;
3. enable `allow_unsigned_preview` for that individual workflow run; and
4. confirm `compatibility.json` uses `channel: preview` and the version has a
   matching `-preview.*` identity.

A tag-triggered run has no unsigned opt-in and therefore still fails when signing
secrets are absent. The exception is never inferred merely from a missing secret.
The Windows file is renamed with `-UNSIGNED-PREVIEW.exe`. The GitHub prerelease
warning, release manifest, `scout-bee-windows-signing.json`, `SHA256SUMS`, and
repository-bound attestation record or cover the exact unsigned bytes. The Linux
archive and supply-chain metadata are still produced, checksummed, and attested.

Before publishing, inspect the resolved policy line in the Windows job and the
signing metadata in the assembled publish job. A checksum or GitHub attestation is
not an Authenticode signature; these are separate controls.

Stable is the eventual default end-user channel. Preview and RC releases must be
selected explicitly. A release must not be promoted until clean Windows, remote
Linux, Cloudflare, recovery, negative verification, accessibility, and secret-scan
evidence is attached to the release decision.
