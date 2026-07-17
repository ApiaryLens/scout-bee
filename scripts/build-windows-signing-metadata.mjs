import { mkdirSync, readdirSync, readFileSync, writeFileSync } from "node:fs";
import { pathToFileURL } from "node:url";

export function createWindowsSigningMetadata({
  version,
  channel,
  artifact,
  signingMode,
  explicitUnsignedPreviewOptIn = false,
}) {
  if (!["signed", "unsigned-preview"].includes(signingMode)) {
    throw new Error(
      `Unsupported Windows signing mode: ${signingMode ?? "<missing>"}.`,
    );
  }
  if (
    signingMode === "unsigned-preview" &&
    (channel !== "preview" || !explicitUnsignedPreviewOptIn)
  ) {
    throw new Error(
      "Unsigned Windows metadata is permitted only for an explicitly opted-in Preview release.",
    );
  }
  if (
    signingMode === "unsigned-preview" &&
    !artifact.endsWith("-UNSIGNED-PREVIEW.exe")
  ) {
    throw new Error(
      "An unsigned Preview executable must carry the unsigned filename suffix.",
    );
  }
  if (signingMode === "signed" && artifact.includes("-UNSIGNED-PREVIEW.exe")) {
    throw new Error(
      "A signed executable cannot carry the unsigned filename suffix.",
    );
  }
  return {
    schemaVersion: 1,
    scoutVersion: version,
    channel,
    artifact,
    signingMode,
    explicitUnsignedPreviewOptIn,
    authenticode:
      signingMode === "signed"
        ? {
            status: "signed",
            digest: "SHA256",
            timestamped: true,
            verification: "signtool verify /pa /all",
          }
        : {
            status: "unsigned",
            reason: "preview-explicit-opt-in-signing-secrets-unavailable",
          },
  };
}

function run() {
  const version = readFileSync("VERSION", "utf8").trim();
  const compatibility = JSON.parse(readFileSync("compatibility.json", "utf8"));
  const signingMode = process.env.SCOUT_WINDOWS_SIGNING_MODE;
  const explicitUnsignedPreviewOptIn =
    process.env.SCOUT_EXPLICIT_UNSIGNED_PREVIEW_OPT_IN === "true";
  const artifacts = readdirSync("dist").filter(
    (name) =>
      name.startsWith(`scout-bee-${version}-windows-amd64`) &&
      name.endsWith(".exe"),
  );
  if (artifacts.length !== 1) {
    throw new Error(
      `Expected one Windows executable, found ${artifacts.length}.`,
    );
  }
  const metadata = createWindowsSigningMetadata({
    version,
    channel: compatibility.channel,
    artifact: artifacts[0],
    signingMode,
    explicitUnsignedPreviewOptIn,
  });
  mkdirSync("dist", { recursive: true });
  writeFileSync(
    "dist/scout-bee-windows-signing.json",
    `${JSON.stringify(metadata, null, 2)}\n`,
  );
}

if (
  process.argv[1] &&
  import.meta.url === pathToFileURL(process.argv[1]).href
) {
  run();
}
