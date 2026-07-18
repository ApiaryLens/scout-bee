export type Target =
  "windows-client" | "cloudflare" | "compose-ssh" | "plan-only";

export type TargetDefinition = {
  id: Target;
  title: string;
  subtitle: string;
  description: string;
};

// The full catalog of deployment homes Scout Bee knows how to guide.
// The Windows client target is feature-flagged: ADR 0023 (2026-07-18) ships
// Scout bootstrap-scoped, so windows-client is hidden unless the server
// reports SCOUT_BEE_ENABLE_WINDOWS_CLIENT is explicitly set (WIN-031).
export const targetCatalog: readonly TargetDefinition[] = [
  {
    id: "windows-client",
    title: "Windows app",
    subtitle: "Standalone on this computer",
    description:
      "Installs or manages the signed ApiaryLens Windows application without requiring Linux, WSL, Docker, Node, or Go.",
  },
  {
    id: "cloudflare",
    title: "Family Cloud",
    subtitle: "Available across your devices",
    description:
      "Runs in your own Cloudflare account. Predictably near-zero cost for a family apiary, subject to provider allowances.",
  },
  {
    id: "compose-ssh",
    title: "My Own Hardware or VM",
    subtitle: "Maximum ownership and portability",
    description:
      "Installs the released Docker Compose package on an ordinary Linux server you control.",
  },
  {
    id: "plan-only",
    title: "Advanced plan",
    subtitle: "Review or automate later",
    description: "Creates a validated, secret-free plan without applying it.",
  },
] as const;

export function availableTargets(
  windowsClientEnabled: boolean,
): TargetDefinition[] {
  return targetCatalog.filter(
    (definition) => definition.id !== "windows-client" || windowsClientEnabled,
  );
}
