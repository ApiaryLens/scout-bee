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

const tag =
  process.env.GITHUB_REF_TYPE === "tag" ? process.env.GITHUB_REF_NAME : "";
if (tag && tag !== `v${version}`) {
  throw new Error(
    `Release tag ${tag} does not match Scout version v${version}`,
  );
}

process.stdout.write(`Scout version ${version} is internally consistent.\n`);
