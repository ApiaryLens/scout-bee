import { execFileSync } from "node:child_process";
import { randomUUID } from "node:crypto";
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";

const packageMetadata = JSON.parse(readFileSync("package.json", "utf8"));
const version = readFileSync("VERSION", "utf8").trim();
const pnpmCli = process.env.npm_execpath;
if (!pnpmCli) {
  throw new Error("pnpm must invoke the supply-chain build");
}
const licenses = JSON.parse(
  execFileSync(
    process.execPath,
    [pnpmCli, "licenses", "list", "--json", "--prod"],
    { encoding: "utf8" },
  ),
);

const components = Object.entries(licenses)
  .flatMap(([license, packages]) =>
    packages.flatMap((dependency) =>
      dependency.versions.map((dependencyVersion) => ({
        type: "library",
        name: dependency.name,
        version: dependencyVersion,
        licenses: [{ license: { id: license } }],
        purl: `pkg:npm/${encodeURIComponent(dependency.name)}@${dependencyVersion}`,
      })),
    ),
  )
  .sort((left, right) =>
    `${left.name}@${left.version}`.localeCompare(
      `${right.name}@${right.version}`,
    ),
  );

const sbom = {
  bomFormat: "CycloneDX",
  specVersion: "1.6",
  serialNumber: `urn:uuid:${randomUUID()}`,
  version: 1,
  metadata: {
    timestamp: new Date().toISOString(),
    component: {
      type: "application",
      name: "Scout Bee",
      version,
      licenses: [{ license: { id: packageMetadata.license } }],
      purl: `pkg:github/ApiaryLens/scout-bee@${version}`,
    },
  },
  components,
};

const licenseRows = components.map(
  (component) =>
    `| ${component.name} | ${component.version} | ${component.licenses[0].license.id} |`,
);
const report = `# Scout Bee release license report

Scout Bee ${version} is licensed under Apache-2.0. The embedded production UI
dependencies reported by the locked package manager are listed below. Go executor
code currently uses only the Go standard library.

| Component | Version | License |
|---|---|---|
${licenseRows.join("\n")}
`;

mkdirSync("dist", { recursive: true });
writeFileSync(
  "dist/scout-bee-sbom.cdx.json",
  `${JSON.stringify(sbom, null, 2)}\n`,
);
writeFileSync("dist/scout-bee-license-report.md", report);
