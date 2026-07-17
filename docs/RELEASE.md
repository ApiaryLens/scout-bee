# Scout Bee release procedure

Scout Bee versions and tags are independent from ApiaryLens product versions. A
release tag is `v<scoutVersion>` and must match `VERSION`, `package.json`, and
`compatibility.json` exactly.

The release workflow:

1. builds the embedded interface from locked dependencies;
2. runs Go and UI verification;
3. builds a portable Windows AMD64 executable and Linux AMD64 executable;
4. Authenticode-signs and timestamps the Windows executable;
5. packages the Linux executable with a concise release README;
6. creates SHA-256 and compatibility metadata;
7. creates repository-bound GitHub attestations; and
8. uploads immutable files to the matching GitHub Release.

The workflow deliberately fails when the Windows signing certificate is absent.
The certificate and password are repository secrets named
`WINDOWS_SIGNING_CERTIFICATE_BASE64` and `WINDOWS_SIGNING_CERTIFICATE_PASSWORD`.
They must never be written to source, logs, manifests, diagnostics, or artifacts.

Stable is the eventual default end-user channel. Preview and RC releases must be
selected explicitly. A release must not be promoted until clean Windows, remote
Linux, Cloudflare, recovery, negative verification, accessibility, and secret-scan
evidence is attached to the release decision.
