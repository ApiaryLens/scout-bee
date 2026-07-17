# Contributing

Scout Bee is an Apache-2.0 project. Contributor source builds are separate from the
normal end-user installation path.

Before proposing a change:

1. preserve the loopback, secret-handling, artifact-verification, and target-isolation
   boundaries described in `SECURITY.md`;
2. keep ApiaryLens product contracts and artifacts authoritative in the core
   `ApiaryLens/apiarylens` repository;
3. add tests for lifecycle, validation, redaction, and recovery behavior; and
4. run `pnpm verify`.

Do not commit generated `ui-dist`, binaries, dependency directories, credentials,
tokens, private keys, personal deployment plans, or diagnostic bundles.
