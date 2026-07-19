export type Target =
  "windows-client" | "cloudflare" | "compose-ssh" | "plan-only";

export type TargetDefinition = {
  id: Target;
  title: string;
  flag: string;
  description: string;
  bestFor: string;
};

// The full catalog of deployment homes Scout Bee knows how to guide, in the
// V1 "Wizard Classic" choice-card grammar (owner-selected design, 2026-07-19).
// The Windows client target is feature-flagged: ADR 0023 (2026-07-18) ships
// Scout bootstrap-scoped, so windows-client is hidden unless the server
// reports SCOUT_BEE_ENABLE_WINDOWS_CLIENT is explicitly set (WIN-031).
export const targetCatalog: readonly TargetDefinition[] = [
  {
    id: "windows-client",
    title: "Just on this computer",
    flag: "Windows app",
    description:
      "Installs or manages the ApiaryLens Windows application without requiring Linux, WSL, Docker, Node, or Go. Scout verifies the exact package identity before any lifecycle work.",
    bestFor: "one shared family computer.",
  },
  {
    id: "cloudflare",
    title: "With a cloud backend",
    flag: "Your own Cloudflare account",
    description:
      "ApiaryLens runs in a Cloudflare account that belongs to you, so the whole family can use it from any device. A family's records usually fit Cloudflare's free tier. You'll need a Cloudflare account and an API token during setup — Scout uses the token once and never stores it.",
    bestFor: "a family spread across phones, tablets, and houses.",
  },
  {
    id: "compose-ssh",
    title: "On our own server",
    flag: "SSH · Docker Compose",
    description:
      "For a home server or NAS you already run. Scout connects over SSH, checks the server's identity fingerprint against the one you give it, and installs with Docker Compose. You look after the machine; Scout helps with installing, updating, backing up, and repairs.",
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

export function availableTargets(
  windowsClientEnabled: boolean,
): TargetDefinition[] {
  return targetCatalog.filter(
    (definition) => definition.id !== "windows-client" || windowsClientEnabled,
  );
}
