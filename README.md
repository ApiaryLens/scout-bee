# Scout Bee

Scout Bee is the separately released ApiaryLens installer, updater, recovery tool,
and deployment manager. It provides a guided interface for installing and managing
exact ApiaryLens product releases on Windows, Cloudflare, and remote Linux hosts.

Scout Bee and ApiaryLens have independent versions. Scout consumes immutable product
release manifests and artifacts; it does not build or copy ApiaryLens product source.

## Repository transition status

This repository is the staged successor to `apps/scout-bee` in the ApiaryLens core
repository. The core copy remains in place as frozen compatibility input until this
repository publishes and verifies a replacement release. Do not use both copies to
ship the same Scout version.

## End-user packages

End users should install Scout Bee from a signed GitHub Release package, not from a
source clone. The intended release formats are:

- one portable Windows executable; and
- one Linux archive containing a single executable and a concise README.

The Windows package does not require Go, Node.js, WSL, or a Linux shell. Source
dependencies below are for contributors only.

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
