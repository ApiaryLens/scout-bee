// Resolve the Scout launch token from the current URL.
//
// The token is a per-launch, in-memory credential (see AGENTS.md). It is
// deliberately NOT persisted to localStorage / sessionStorage / cookies, so it
// never survives Scout exiting and is never exposed to a later page served on
// the same loopback origin.
//
// It is delivered as the "k" query parameter rather than a URL "#fragment":
// on Windows the opener (rundll32 url.dll,FileProtocolHandler) strips everything
// after "#", which left the auto-opened window tokenless and stuck on "Scout Bee
// launch authorization is required". Query params survive the OS URL openers on
// every platform, and — unlike a fragment consumed once — they stay in the URL,
// so reloading the launched tab keeps working. A bare-URL tab with no token
// intentionally has none: relaunch Scout to mint a fresh one.
export function resolveLaunchToken(search: string, hash: string): string {
  return (
    new URLSearchParams(search).get("k") ??
    (hash.startsWith("#") ? hash.slice(1) : hash)
  );
}
