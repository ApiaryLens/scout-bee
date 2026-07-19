import { describe, it, expect } from "vitest";
import { resolveLaunchToken } from "./launch-token";

describe("resolveLaunchToken", () => {
  it("reads the token from the ?k= query param", () => {
    expect(resolveLaunchToken("?k=abc123", "")).toBe("abc123");
  });

  it("falls back to the legacy #fragment token", () => {
    expect(resolveLaunchToken("", "#hashtok")).toBe("hashtok");
  });

  it("prefers the query param over a fragment", () => {
    expect(resolveLaunchToken("?k=fromquery", "#fromhash")).toBe("fromquery");
  });

  it("returns an empty string for a bare URL with no token", () => {
    expect(resolveLaunchToken("", "")).toBe("");
  });

  it("does not treat other query params as the token", () => {
    expect(resolveLaunchToken("?other=1", "")).toBe("");
  });
});
