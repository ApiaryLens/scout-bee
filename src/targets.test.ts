import { describe, expect, it } from "vitest";
import { availableTargets, targetCatalog } from "./targets";

describe("windows_client feature flag (WIN-031)", () => {
  it("hides the Windows client target when the flag is off (the default)", () => {
    const targets = availableTargets(false);
    expect(targets.map((definition) => definition.id)).toEqual([
      "cloudflare",
      "compose-ssh",
      "plan-only",
    ]);
    expect(
      targets.some((definition) => definition.id === "windows-client"),
    ).toBe(false);
  });

  it("offers the Windows client target only when explicitly enabled", () => {
    const targets = availableTargets(true);
    expect(targets.map((definition) => definition.id)).toEqual([
      "windows-client",
      "cloudflare",
      "compose-ssh",
      "plan-only",
    ]);
  });

  it("keeps the full catalog intact so no lifecycle surface is deleted", () => {
    expect(targetCatalog).toHaveLength(4);
  });
});
