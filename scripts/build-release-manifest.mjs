import { createHash } from "node:crypto";
import { readdirSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { basename, join } from "node:path";

const version = readFileSync("VERSION", "utf8").trim();
const compatibility = JSON.parse(readFileSync("compatibility.json", "utf8"));
const sourceCommit = process.env.GITHUB_SHA ?? "local";
const sourceRef = process.env.GITHUB_REF ?? "local";

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
    };
  });

if (artifacts.length !== 2) {
  throw new Error(
    `Expected exactly two Scout release packages, found ${artifacts.length}`,
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
  artifacts,
  releaseMetadata: [
    describeFile("scout-bee-sbom.cdx.json"),
    describeFile("scout-bee-license-report.md"),
  ],
};

writeFileSync(
  "dist/scout-bee-release-manifest.json",
  `${JSON.stringify(manifest, null, 2)}\n`,
);
