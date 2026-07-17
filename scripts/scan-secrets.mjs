import { execFileSync } from "node:child_process";
import { readFile } from "node:fs/promises";
import { extname, resolve } from "node:path";

const root = resolve(import.meta.dirname, "..");
const tracked = execFileSync(
  "git",
  ["ls-files", "--cached", "--others", "--exclude-standard", "-z"],
  {
    cwd: root,
    encoding: "utf8",
  },
)
  .split("\0")
  .filter(Boolean);

const binaryExtensions = new Set([
  ".exe",
  ".gif",
  ".gz",
  ".ico",
  ".jpeg",
  ".jpg",
  ".pdf",
  ".png",
  ".tar",
  ".webp",
  ".zip",
]);
const rules = [
  ["private-key", /-----BEGIN (?:EC |OPENSSH |PGP |RSA )?PRIVATE KEY-----/g],
  ["aws-access-key", /\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/g],
  [
    "github-token",
    /\b(?:gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{50,255})\b/g,
  ],
  ["slack-token", /\bxox[baprs]-[A-Za-z0-9-]{20,}\b/g],
  ["openai-key", /\bsk-(?:proj-)?[A-Za-z0-9_-]{32,}\b/g],
  ["azure-storage-key", /\bAccountKey=[A-Za-z0-9+/]{40,}={0,2}\b/g],
  ["credential-in-url", /https?:\/\/[^\s/:@]+:[^\s/@]+@/g],
];

const findings = [];
for (const relativePath of tracked) {
  if (binaryExtensions.has(extname(relativePath).toLowerCase())) continue;
  const content = await readFile(resolve(root, relativePath), "utf8").catch(
    () => undefined,
  );
  if (content === undefined || content.includes("\0")) continue;
  for (const [rule, expression] of rules) {
    expression.lastIndex = 0;
    for (const match of content.matchAll(expression)) {
      const line = content.slice(0, match.index).split(/\r?\n/).length;
      findings.push(`${relativePath}:${line} (${rule})`);
    }
  }
}

if (findings.length > 0) {
  console.error(
    `Potential committed secrets detected:\n${findings.join("\n")}`,
  );
  process.exit(1);
}
console.log(
  `Secret-pattern scan passed across ${tracked.length} repository files.`,
);
