import { appendFileSync, readFileSync } from "node:fs";
import { pathToFileURL } from "node:url";

const booleanValue = (value) => String(value).toLowerCase() === "true";

export function resolveReleasePolicy({
  version,
  channel,
  allowUnsignedPreview = false,
  signingMaterialAvailable = false,
}) {
  const expectedChannel = version.includes("-preview.")
    ? "preview"
    : version.includes("-rc.")
      ? "rc"
      : version.includes("-")
        ? "unsupported"
        : "stable";
  if (channel !== expectedChannel) {
    throw new Error(
      `Scout version ${version} requires channel ${expectedChannel}, not ${channel}.`,
    );
  }
  if (!["preview", "rc", "stable"].includes(channel)) {
    throw new Error(`Unsupported Scout release channel: ${channel}.`);
  }
  if (signingMaterialAvailable) {
    return {
      version,
      channel,
      signingMode: "signed",
      explicitUnsignedPreviewOptIn: false,
    };
  }
  if (channel === "preview" && allowUnsignedPreview) {
    return {
      version,
      channel,
      signingMode: "unsigned-preview",
      explicitUnsignedPreviewOptIn: true,
    };
  }
  throw new Error(
    channel === "preview"
      ? "Windows signing secrets are absent. Re-run this Preview from its tag with allow_unsigned_preview explicitly enabled, or configure both signing secrets."
      : `${channel.toUpperCase()} releases require Authenticode signing secrets and cannot be published unsigned.`,
  );
}

function run() {
  const version = readFileSync("VERSION", "utf8").trim();
  const compatibility = JSON.parse(readFileSync("compatibility.json", "utf8"));
  const policy = resolveReleasePolicy({
    version,
    channel: compatibility.channel,
    allowUnsignedPreview: booleanValue(
      process.env.SCOUT_ALLOW_UNSIGNED_PREVIEW,
    ),
    signingMaterialAvailable: booleanValue(
      process.env.SCOUT_WINDOWS_SIGNING_AVAILABLE,
    ),
  });
  const output = process.env.GITHUB_OUTPUT;
  if (output) {
    appendFileSync(output, `version=${policy.version}\n`);
    appendFileSync(output, `channel=${policy.channel}\n`);
    appendFileSync(output, `signing_mode=${policy.signingMode}\n`);
    appendFileSync(
      output,
      `explicit_unsigned_preview_opt_in=${policy.explicitUnsignedPreviewOptIn}\n`,
    );
  }
  process.stdout.write(
    `Scout ${policy.version} release policy: ${policy.channel}, ${policy.signingMode}.\n`,
  );
}

if (
  process.argv[1] &&
  import.meta.url === pathToFileURL(process.argv[1]).href
) {
  run();
}
