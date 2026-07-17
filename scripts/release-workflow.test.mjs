import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";

const workflow = readFileSync(".github/workflows/release.yml", "utf8");
const manifestBuilder = readFileSync(
  "scripts/build-release-manifest.mjs",
  "utf8",
);

describe("Scout release workflow policy wiring", () => {
  it("requires an explicit per-run unsigned Preview input", () => {
    expect(workflow).toContain("allow_unsigned_preview:");
    expect(workflow).toContain("required: true");
    expect(workflow).toContain("default: false");
    expect(workflow).toContain("node scripts/release-policy.mjs");
  });

  it("signs only the signed policy branch and labels the unsigned Preview bytes", () => {
    expect(workflow).toContain(
      "if: steps.release-policy.outputs.signing_mode == 'signed'",
    );
    expect(workflow).toContain(
      "if: steps.release-policy.outputs.signing_mode == 'unsigned-preview'",
    );
    expect(workflow).toContain("-UNSIGNED-PREVIEW.exe");
    expect(workflow).toContain("scout-bee-windows-signing.json");
  });

  it("attests and checksums the signing evidence with both packages", () => {
    expect(workflow).toContain("dist/scout-bee-*-windows-amd64*.exe");
    expect(workflow).toContain("dist/scout-bee-*-linux-amd64.tar.gz");
    expect(workflow).toContain("dist/scout-bee-windows-signing.json");
    expect(workflow).toContain("sha256sum scout-bee-*");
    expect(manifestBuilder).toContain(
      'describeFile("scout-bee-windows-signing.json")',
    );
    expect(manifestBuilder).toContain("explicitUnsignedPreviewOptIn");
  });
});
