export type Target =
  | "windows-client"
  | "compose-local"
  | "cloudflare"
  | "compose-ssh"
  | "plan-only";

export type TargetDefinition = {
  id: Target;
  title: string;
  flag: string;
  description: string;
  bestFor: string;
};

// The full catalog of deployment homes Scout Bee knows how to guide, in the
// V1 "Wizard Classic" choice-card grammar (owner-selected design, 2026-07-19).
// Owner wording rules: Cloudflare is the only managed/no-server option; any
// rented cloud VM (Azure, AWS, ...) is the own-server Compose path. The
// local-machine trial is the released Compose bundle on WSL2/Docker.
// The Windows client target is feature-flagged: ADR 0023 (2026-07-18) ships
// Scout bootstrap-scoped, so windows-client is hidden unless the server
// reports SCOUT_BEE_ENABLE_WINDOWS_CLIENT is explicitly set (WIN-031). The
// choice screen still shows it as an honest "coming soon" placeholder inside
// the local-machine card.
export const targetCatalog: readonly TargetDefinition[] = [
  {
    id: "windows-client",
    title: "Windows app",
    flag: "No Docker · No WSL",
    description:
      "A native ApiaryLens Windows application installed and managed by Scout without Docker or WSL. It is being rewritten and ships in a later phase.",
    bestFor: "one shared family computer, once it ships.",
  },
  {
    id: "compose-local",
    title: "Test or trial on this computer",
    flag: "WSL / Docker",
    description:
      "Runs the released ApiaryLens package on this computer using WSL2 with Docker (Docker Desktop) on Windows, or Docker on Linux. Everything stays on this machine at http://localhost — ideal for trying ApiaryLens out. Because this computer holds the only copy, Scout will help you make backup files.",
    bestFor: "trying ApiaryLens before choosing its long-term home.",
  },
  {
    id: "cloudflare",
    title: "With a cloud backend",
    flag: "Managed · your Cloudflare account",
    description:
      "The managed, no-server option, powered by Cloudflare: ApiaryLens runs in a Cloudflare account that belongs to you, so the whole family can use it from any device. A family's records usually fit Cloudflare's free tier. You'll need a Cloudflare account and an API token during setup — Scout uses the token once and never stores it. (To use another cloud such as Azure or AWS, rent a VM there and pick \"On our own server\".)",
    bestFor: "a family spread across phones, tablets, and houses.",
  },
  {
    id: "compose-ssh",
    title: "On our own server",
    flag: "SSH · Docker Compose",
    description:
      "For a computer you control — a home server, a NAS, or a cloud VM you rent (Azure, AWS, Hetzner, etc.). Scout connects over SSH, checks the server's identity fingerprint against the one you give it, and installs with Docker Compose. You look after the machine; Scout helps with installing, updating, backing up, and repairs.",
    bestFor: "families with a confident self-hoster.",
  },
  {
    id: "plan-only",
    title: "Advanced plan",
    flag: "Review or automate later",
    description:
      "Creates a validated, secret-free deployment plan file without applying it, so you can review it or run it later.",
    bestFor: "operators who review everything first.",
  },
] as const;

// Per-setup default folders (owner UAT 2026-07-19): the local trial defaults
// to a home-relative folder because a normal WSL/Linux user cannot create
// /opt/... without sudo; server installs keep /opt where root access is an
// expected part of running a server.
export const setupDefaults = {
  "compose-local": { installDirectory: "~/apiarylens", httpPort: 8420 },
  "compose-ssh": { targetDirectory: "/opt/apiarylens" },
} as const;

export function availableTargets(
  windowsClientEnabled: boolean,
): TargetDefinition[] {
  return targetCatalog.filter(
    (definition) => definition.id !== "windows-client" || windowsClientEnabled,
  );
}
