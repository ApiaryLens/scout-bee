# Scout Bee

Scout Bee is the separately released ApiaryLens installer, updater, recovery tool,
and deployment manager. It provides a guided interface for installing and managing
exact ApiaryLens product releases on Windows, Cloudflare, and remote Linux hosts.

Scout Bee and ApiaryLens have independent versions. Scout consumes immutable product
release manifests and artifacts; it does not build or copy ApiaryLens product source.

## Repository status

This is the authoritative Scout Bee source repository. The former embedded
`apps/scout-bee` implementation has been removed from the ApiaryLens core repository.
Core publishes product contracts and immutable release artifacts; Scout consumes
them without copying or deploying product source.

## End-user packages

End users should install Scout Bee from a signed GitHub Release package, not from a
source clone. The intended release formats are:

- one portable Windows executable; and
- one Linux archive containing a single executable and a concise README.

The Windows package does not require Go, Node.js, WSL, or a Linux shell. Source
dependencies below are for contributors only.

Stable is the default product channel. Preview and release-candidate products appear
only after explicit selection under **Advanced release channel**. Verified product
artifacts are cached by checksum in the user's Scout Bee cache for safe resume,
repair, and rollback. Scout supports install, update, repair, rollback, backup,
restore, export, and keep-data or remove-data uninstall operations.

After a successful install, update, repair, or rollback, Scout can save a
secret-free `apiarylens-windows-connection.json`. Import it with
`ApiaryLens.exe --desktop-profile=<absolute-json-path>`. The Windows application
verifies the exact HTTPS deployment and release contracts before persisting the
connection. The file never contains an account password, session, provider token,
SSH key, deployment secret, or recovery code.

## Contributor build

Prerequisites:

- Node.js 24 or newer
- pnpm 11.7.0
- Go 1.26 or newer

```powershell
corepack enable
pnpm install --frozen-lockfile
pnpm verify
```

`pnpm build` compiles the embedded React interface into `ui-dist` and then builds
the local Go executor. `pnpm test:go` also builds the interface first because the Go
binary embeds those generated assets.

## Security boundary

Scout binds its embedded interface to a random loopback port and authorizes API
requests with a per-launch, in-memory value. Deployment plans are secret-free.
Credentials are accepted only during an operation and must not enter plans, logs,
diagnostics, caches, or exported repositories.

Report security issues using [SECURITY.md](SECURITY.md).

## Ownership boundary

This repository owns the Scout UI, executor, target adapters, lifecycle state,
packaging, tests, diagnostics, self-update, and Scout release workflows.

The `ApiaryLens/apiarylens` repository remains authoritative for product contracts,
migrations, deployment templates, manifests, checksums, SBOMs, attestations, and
immutable ApiaryLens artifacts.

## License

Apache License 2.0. See [LICENSE](LICENSE).
