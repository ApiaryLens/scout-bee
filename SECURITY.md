# Security policy

Do not open a public issue for a vulnerability that could expose deployment
credentials, private hive data, media, signing material, or a user's infrastructure.
Use GitHub's private vulnerability reporting for the `ApiaryLens/scout-bee`
repository when it is available.

Scout Bee must preserve these invariants:

- the local HTTP service binds only to loopback;
- every API request requires the per-launch authorization value;
- plans, logs, diagnostics, exports, and repository files contain no secrets;
- release artifacts are verified before execution or extraction;
- SSH host identity changes stop execution; and
- destructive operations require explicit confirmation and verified recovery state.
