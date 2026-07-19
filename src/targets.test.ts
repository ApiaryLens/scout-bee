import { describe, expect, it } from "vitest";
import { availableTargets, setupDefaults, targetCatalog } from "./targets";

describe("windows_client feature flag (WIN-031)", () => {
  it("hides the Windows client target when the flag is off (the default)", () => {
    const targets = availableTargets(false);
    expect(targets.map((definition) => definition.id)).toEqual([
      "compose-local",
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
      "compose-local",
      "cloudflare",
      "compose-ssh",
      "plan-only",
    ]);
  });

  it("keeps the full catalog intact so no lifecycle surface is deleted", () => {
    expect(targetCatalog).toHaveLength(5);
  });
});

describe("owner wording rules (2026-07-19)", () => {
  it("keeps Cloudflare as the only managed option and points other clouds at the own-server Compose path", () => {
    const cloudflare = targetCatalog.find((d) => d.id === "cloudflare");
    const ownServer = targetCatalog.find((d) => d.id === "compose-ssh");
    expect(cloudflare?.description).toContain("managed, no-server");
    expect(cloudflare?.description).toContain("On our own server");
    expect(ownServer?.description).toContain("cloud VM you rent");
  });

  it("presents the local trial honestly with no sync affordance", () => {
    const local = targetCatalog.find((d) => d.id === "compose-local");
    expect(local?.description).toContain("this computer");
    expect(local?.description).toContain("backup");
    expect(local?.description.toLowerCase()).not.toContain("sync");
  });
});

describe("per-setup install-folder defaults (owner UAT 2026-07-19)", () => {
  it("defaults the local trial to a sudo-free home folder, never /opt", () => {
    expect(
      setupDefaults["compose-local"].installDirectory.startsWith("~/"),
    ).toBe(true);
    expect(setupDefaults["compose-local"].installDirectory).not.toContain(
      "/opt",
    );
    expect(setupDefaults["compose-local"].httpPort).toBeGreaterThan(1024);
  });

  it("never bakes a concrete username into the default — the shell resolves ~ at run time", () => {
    expect(setupDefaults["compose-local"].installDirectory).not.toMatch(
      /\/home\/|\/Users\//,
    );
  });

  it("keeps /opt for server installs where root access is expected", () => {
    expect(setupDefaults["compose-ssh"].targetDirectory).toBe(
      "/opt/apiarylens",
    );
  });
});
