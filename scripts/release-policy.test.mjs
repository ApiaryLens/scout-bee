import { describe, expect, it } from "vitest";
import { createWindowsSigningMetadata } from "./build-windows-signing-metadata.mjs";
import { resolveReleasePolicy } from "./release-policy.mjs";

describe("Scout release signing policy", () => {
  it("allows an explicitly opted-in unsigned Preview when signing material is absent", () => {
    expect(
      resolveReleasePolicy({
        version: "0.1.0-preview.2",
        channel: "preview",
        allowUnsignedPreview: true,
        signingMaterialAvailable: false,
      }),
    ).toMatchObject({
      signingMode: "unsigned-preview",
      explicitUnsignedPreviewOptIn: true,
    });
  });

  it.each([
    ["0.1.0-preview.2", "preview"],
    ["0.1.0-rc.1", "rc"],
    ["0.1.0", "stable"],
  ])(
    "uses Authenticode when signing material exists for %s",
    (version, channel) => {
      expect(
        resolveReleasePolicy({
          version,
          channel,
          signingMaterialAvailable: true,
        }),
      ).toMatchObject({ signingMode: "signed" });
    },
  );

  it.each([
    ["0.1.0-preview.2", "preview", false],
    ["0.1.0-rc.1", "rc", true],
    ["0.1.0", "stable", true],
  ])(
    "fails closed without signing material for %s",
    (version, channel, allowUnsignedPreview) => {
      expect(() =>
        resolveReleasePolicy({
          version,
          channel,
          allowUnsignedPreview,
          signingMaterialAvailable: false,
        }),
      ).toThrow();
    },
  );

  it("rejects a version whose prerelease identity disagrees with the channel", () => {
    expect(() =>
      resolveReleasePolicy({
        version: "0.1.0-rc.1",
        channel: "preview",
        allowUnsignedPreview: true,
      }),
    ).toThrow(/requires channel rc/);
  });
});

describe("Windows signing evidence", () => {
  it("records an explicitly unsigned Preview without claiming Authenticode", () => {
    expect(
      createWindowsSigningMetadata({
        version: "0.1.0-preview.2",
        channel: "preview",
        artifact:
          "scout-bee-0.1.0-preview.2-windows-amd64-UNSIGNED-PREVIEW.exe",
        signingMode: "unsigned-preview",
        explicitUnsignedPreviewOptIn: true,
      }),
    ).toMatchObject({
      signingMode: "unsigned-preview",
      authenticode: { status: "unsigned" },
    });
  });

  it("refuses unsigned metadata for RC or Stable and requires the visible suffix", () => {
    expect(() =>
      createWindowsSigningMetadata({
        version: "0.1.0-rc.1",
        channel: "rc",
        artifact: "scout-bee-0.1.0-rc.1-windows-amd64-UNSIGNED-PREVIEW.exe",
        signingMode: "unsigned-preview",
        explicitUnsignedPreviewOptIn: true,
      }),
    ).toThrow(/only for an explicitly opted-in Preview/);
    expect(() =>
      createWindowsSigningMetadata({
        version: "0.1.0-preview.2",
        channel: "preview",
        artifact: "scout-bee-0.1.0-preview.2-windows-amd64.exe",
        signingMode: "unsigned-preview",
        explicitUnsignedPreviewOptIn: true,
      }),
    ).toThrow(/unsigned filename suffix/);
  });
});
