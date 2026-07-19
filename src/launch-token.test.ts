import { describe, it, expect } from "vitest";
import {
  resolveLaunchToken,
  LAUNCH_TOKEN_STORAGE_KEY,
  type TokenStore,
} from "./launch-token";

function memoryStore(): TokenStore & { map: Map<string, string> } {
  const map = new Map<string, string>();
  return {
    map,
    getItem: (k) => map.get(k) ?? null,
    setItem: (k, v) => {
      map.set(k, v);
    },
  };
}

describe("resolveLaunchToken", () => {
  it("reads the token from the ?k= query param and persists it", () => {
    const store = memoryStore();
    expect(resolveLaunchToken("?k=abc123", "", store)).toBe("abc123");
    expect(store.map.get(LAUNCH_TOKEN_STORAGE_KEY)).toBe("abc123");
  });

  it("falls back to the legacy #fragment token", () => {
    expect(resolveLaunchToken("", "#hashtok", memoryStore())).toBe("hashtok");
  });

  it("recovers the token from storage on a bare URL — the reload / 2nd-tab case", () => {
    const store = memoryStore();
    resolveLaunchToken("?k=persisted", "", store); // first (auto-opened) tab
    // A later bare-URL load (reload, manual open, second tab) has no token in
    // the URL and must NOT dead-end on the authorization banner.
    expect(resolveLaunchToken("", "", store)).toBe("persisted");
  });

  it("returns an empty string when no token is present anywhere", () => {
    expect(resolveLaunchToken("", "", memoryStore())).toBe("");
  });

  it("still returns the in-URL token when storage is unavailable", () => {
    expect(resolveLaunchToken("?k=xyz", "", null)).toBe("xyz");
  });

  it("prefers a fresh in-URL token over a stale stored one", () => {
    const store = memoryStore();
    resolveLaunchToken("?k=old", "", store);
    expect(resolveLaunchToken("?k=new", "", store)).toBe("new");
    expect(store.map.get(LAUNCH_TOKEN_STORAGE_KEY)).toBe("new");
  });
});
