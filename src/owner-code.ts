import type { Target } from "./targets";

// Owner decision (2026-07-19): Scout auto-generates the one-time owner setup
// code by default. The code only guards who gets to claim the first owner
// account, so an app-generated random value is stronger than a human-invented
// one, and a localhost trial should never block on typing one.

// A 32-character alphabet (no 0/O/1/l ambiguity) keeps `byte & 31` unbiased:
// 24 characters yield 120 bits of entropy.
const ownerCodeAlphabet = "abcdefghijkmnpqrstuvwxyz23456789";

export function generateOwnerCode(length = 24): string {
  const bytes = new Uint8Array(length);
  crypto.getRandomValues(bytes);
  return Array.from(bytes, (byte) => ownerCodeAlphabet[byte & 31]).join("");
}

export type OwnerCodeMode = "auto" | "custom";

// ownerCodeReady decides whether the wizard may run an install:
// - auto + local trial: always ready — the code is shown at handoff, never a
//   blocker (there is no exposed backend for a stranger to race).
// - auto + cloud/own-server: ready once the family confirms they saved the
//   shown code (they need it to claim the first owner on an exposed backend).
// - custom: ready once the typed code has at least 16 characters.
export function ownerCodeReady(
  target: Target,
  mode: OwnerCodeMode,
  customCode: string,
  savedConfirmed: boolean,
): boolean {
  if (mode === "custom") return customCode.length >= 16;
  if (target === "compose-local") return true;
  return savedConfirmed;
}
