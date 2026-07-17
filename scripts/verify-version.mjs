import { readFileSync } from "node:fs";

const version = readFileSync("VERSION", "utf8").trim();
const packageVersion = JSON.parse(readFileSync("package.json", "utf8")).version;
const compatibility = JSON.parse(readFileSync("compatibility.json", "utf8"));

if (!/^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/.test(version)) {
  throw new Error(`VERSION is not a semantic version: ${version}`);
}

if (packageVersion !== version || compatibility.scoutVersion !== version) {
  throw new Error(
    `Scout version drift: VERSION=${version}, package=${packageVersion}, compatibility=${compatibility.scoutVersion}`,
  );
}

const expectedChannel = version.includes("-preview.")
  ? "preview"
  : version.includes("-rc.")
    ? "rc"
    : version.includes("-")
      ? "unsupported"
      : "stable";
if (compatibility.channel !== expectedChannel) {
  throw new Error(
    `Scout version ${version} requires compatibility channel ${expectedChannel}, not ${compatibility.channel}`,
  );
}

const supportedProducts = compatibility.supportedProductVersions;
const testedProducts = compatibility.testedProductVersions;
if (
  !Array.isArray(supportedProducts) ||
  supportedProducts.length === 0 ||
  !Array.isArray(testedProducts) ||
  testedProducts.length === 0 ||
  new Set(supportedProducts).size !== supportedProducts.length ||
  new Set(testedProducts).size !== testedProducts.length ||
  supportedProducts.some(
    (productVersion) =>
      typeof productVersion !== "string" ||
      productVersion.length === 0 ||
      !testedProducts.includes(productVersion),
  )
) {
  throw new Error(
    "Every supported product version must be a unique, non-empty tested product version.",
  );
}

const tag =
  process.env.GITHUB_REF_TYPE === "tag" ? process.env.GITHUB_REF_NAME : "";
if (tag && tag !== `v${version}`) {
  throw new Error(
    `Release tag ${tag} does not match Scout version v${version}`,
  );
}

process.stdout.write(`Scout version ${version} is internally consistent.\n`);
