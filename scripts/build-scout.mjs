import { execFileSync } from "node:child_process";
import { mkdirSync, readFileSync } from "node:fs";

const version = readFileSync("VERSION", "utf8").trim();
mkdirSync("dist", { recursive: true });

execFileSync(
  "go",
  [
    "build",
    "-trimpath",
    "-ldflags",
    `-X main.scoutVersion=${version}`,
    "-o",
    "dist/scout-bee",
    ".",
  ],
  { stdio: "inherit" },
);
