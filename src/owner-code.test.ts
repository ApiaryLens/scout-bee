import { describe, expect, it } from "vitest";
import { generateOwnerCode, ownerCodeReady } from "./owner-code";

describe("auto-generated owner setup code (owner decision 2026-07-19)", () => {
  it("meets the 16+ length rule with headroom and a safe alphabet", () => {
    const code = generateOwnerCode();
    expect(code.length).toBeGreaterThanOrEqual(16);
    expect(code).toMatch(/^[abcdefghijkmnpqrstuvwxyz23456789]+$/);
  });

  it("is crypto-random: unique across generations with spread characters", () => {
    const codes = new Set(
      Array.from({ length: 64 }, () => generateOwnerCode()),
    );
    expect(codes.size).toBe(64);
    const distinctCharacters = new Set(
      Array.from(codes).flatMap((code) => code.split("")),
    );
    // 64 samples of 24 characters over a 32-character alphabet should touch
    // essentially the whole alphabet; a broken generator would not.
    expect(distinctCharacters.size).toBeGreaterThan(28);
  });

  it("never blocks the local trial in auto mode (code shown at handoff)", () => {
    expect(ownerCodeReady("compose-local", "auto", "", false)).toBe(true);
  });

  it("requires the family to confirm they saved the shown code for exposed backends", () => {
    expect(ownerCodeReady("cloudflare", "auto", "", false)).toBe(false);
    expect(ownerCodeReady("compose-ssh", "auto", "", false)).toBe(false);
    expect(ownerCodeReady("cloudflare", "auto", "", true)).toBe(true);
    expect(ownerCodeReady("compose-ssh", "auto", "", true)).toBe(true);
  });

  it("keeps the advanced custom-code path with 16+ validation", () => {
    expect(ownerCodeReady("cloudflare", "custom", "short", true)).toBe(false);
    expect(ownerCodeReady("compose-local", "custom", "short", false)).toBe(
      false,
    );
    expect(
      ownerCodeReady("cloudflare", "custom", "a-long-enough-owner-code", false),
    ).toBe(true);
  });
});
