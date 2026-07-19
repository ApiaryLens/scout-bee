// Resolve the Scout launch token.
//
// The token is minted per launch and handed to the browser as the "k" query
// parameter (query params survive the OS URL openers on every platform; a URL
// "#fragment" does NOT — Windows' rundll32 FileProtocolHandler strips it, which
// left the wizard tokenless and stuck on "launch authorization is required").
//
// Once seen, the token is persisted per-origin so a reload, a bare-URL tab, or
// a second tab stays authorized instead of dead-ending on that banner. The
// listening port is unique per launch, so a stored token never leaks across
// Scout runs.
export interface TokenStore {
  getItem(key: string): string | null;
  setItem(key: string, value: string): void;
}

export const LAUNCH_TOKEN_STORAGE_KEY = "scoutLaunchToken";

export function resolveLaunchToken(
  search: string,
  hash: string,
  store: TokenStore | null,
): string {
  const fromUrl =
    new URLSearchParams(search).get("k") ??
    (hash.startsWith("#") ? hash.slice(1) : hash);
  if (fromUrl) {
    try {
      store?.setItem(LAUNCH_TOKEN_STORAGE_KEY, fromUrl);
    } catch {
      // Private mode / storage disabled — the in-URL token still works for
      // this tab; we just can't help bare-URL tabs recover it.
    }
    return fromUrl;
  }
  try {
    return store?.getItem(LAUNCH_TOKEN_STORAGE_KEY) ?? "";
  } catch {
    return "";
  }
}
