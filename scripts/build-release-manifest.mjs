import { createHash } from "node:crypto";
import { readdirSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { basename, join } from "node:path";

const version = readFileSync("VERSION", "utf8").trim();
const compatibility = JSON.parse(readFileSync("compatibility.json", "utf8"));
const sourceCommit = process.env.GITHUB_SHA ?? "local";
const sourceRef = process.env.GITHUB_REF ?? "local";
const windowsSigning = JSON.parse(
  readFileSync("dist/scout-bee-windows-signing.json", "utf8"),
);

function describeFile(name) {
  const path = join("dist", name);
  const bytes = readFileSync(path);
  return {
    name: basename(path),
    bytes: statSync(path).size,
    sha256: createHash("sha256").update(bytes).digest("hex"),
  };
}

const artifacts = readdirSync("dist")
  .filter((name) => name.startsWith(`scout-bee-${version}-`))
  .sort()
  .map((name) => {
    return {
      ...describeFile(name),
      platform: name.includes("-windows-") ? "windows" : "linux",
      architecture: "amd64",
      ...(name.includes("-windows-")
        ? { authenticode: windowsSigning.authenticode }
        : {}),
    };
  });

if (artifacts.length !== 2) {
  throw new Error(
    `Expected exactly two Scout release packages, found ${artifacts.length}`,
  );
}

const windowsArtifact = artifacts.find(
  (artifact) => artifact.platform === "windows",
);
if (
  windowsSigning.scoutVersion !== version ||
  windowsSigning.channel !== compatibility.channel ||
  windowsSigning.artifact !== windowsArtifact?.name
) {
  throw new Error(
    "Windows signing metadata does not match the Scout release artifact.",
  );
}
if (
  windowsSigning.signingMode === "unsigned-preview" &&
  (compatibility.channel !== "preview" ||
    windowsSigning.explicitUnsignedPreviewOptIn !== true ||
    !windowsArtifact.name.includes("-UNSIGNED-PREVIEW.exe"))
) {
  throw new Error(
    "Unsigned Scout packages require explicit Preview identity and metadata.",
  );
}
if (
  windowsSigning.signingMode === "signed" &&
  windowsArtifact.name.includes("-UNSIGNED-PREVIEW.exe")
) {
  throw new Error(
    "A signed Scout package cannot use the unsigned Preview filename.",
  );
}
if (
  windowsSigning.signingMode !== "signed" &&
  windowsSigning.signingMode !== "unsigned-preview"
) {
  throw new Error(
    `Unsupported Windows signing mode: ${windowsSigning.signingMode}`,
  );
}

const manifest = {
  schemaVersion: 1,
  releaseKind: "scout-bee",
  scoutVersion: version,
  channel: compatibility.channel,
  source: {
    repository: "ApiaryLens/scout-bee",
    commit: sourceCommit,
    ref: sourceRef,
  },
  builtAt: new Date().toISOString(),
  compatibility,
  windowsSigning: {
    mode: windowsSigning.signingMode,
    explicitUnsignedPreviewOptIn: windowsSigning.explicitUnsignedPreviewOptIn,
  },
  artifacts,
  releaseMetadata: [
    describeFile("scout-bee-windows-signing.json"),
    describeFile("scout-bee-sbom.cdx.json"),
    describeFile("scout-bee-license-report.md"),
  ],
};

writeFileSync(
  "dist/scout-bee-release-manifest.json",
  `${JSON.stringify(manifest, null, 2)}\n`,
);
