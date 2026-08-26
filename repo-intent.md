# Repo intent — scout-bee

**The separately released ApiaryLens installer, updater, recovery tool, and deployment manager.**

## What this repo is

Scout Bee provides a guided interface for installing and managing exact ApiaryLens
product releases on Windows, Cloudflare, and remote Linux hosts — including a local
test/trial mode that runs the released Compose bundle through WSL2 with Docker on
Windows (or Docker directly on Linux), serving plain HTTP on localhost only.

Scout Bee and ApiaryLens have **independent versions**. Scout consumes immutable
product release manifests and artifacts; it does not build or copy ApiaryLens
product source. This is the authoritative Scout Bee source — the former embedded
`apps/scout-bee` implementation has been removed from the ApiaryLens core repo.

## Shape

- Go source at root (`main.go`, `compose.go`, `cloudflare.go`, `selfupdate.go`,
  `ssh_auth.go`, `windows_client.go`, etc.) — a single-binary installer/updater
- `src/` — a companion frontend (per `vite.config.ts`/`tsconfig.json`)
- End users should install from a verified GitHub Release package (one portable
  Windows executable, one Linux archive), not a source clone

## How it relates to other repos

- **`apiarylens`** — the product this tool installs; consumes its immutable release
  artifacts, never its source directly

## Status

Active — the authoritative, separately-versioned installer for ApiaryLens.
