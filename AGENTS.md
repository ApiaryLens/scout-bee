# Scout Bee agent instructions

Scout Bee is the separately versioned ApiaryLens lifecycle application. Preserve
the ownership boundary accepted by ApiaryLens ADR 0014.

- This repository owns the Scout UI, Go executor, lifecycle adapters, packaging,
  tests, diagnostics, self-update, release metadata, and Scout workflows.
- `ApiaryLens/apiarylens` remains authoritative for product contracts, migrations,
  templates, manifests, and immutable product artifacts. Consume released bytes;
  do not copy product source into this repository.
- Bind the local service only to loopback and authorize every API call with a
  per-launch in-memory value.
- Never put credentials, tokens, passwords, keys, deployment secrets, or private
  target identifiers in plans, logs, diagnostics, caches, exports, or tests.
- Verify repository identity, release identity, attestation, checksum, declared
  size, compatibility, and safe extraction before executing an artifact.
- Stable is the default release channel. Preview and RC require explicit advanced
  opt-in.
- Do not claim a package is signed, verified, or ready based only on a build. Exact
  released-byte lifecycle and negative-path evidence is required.
