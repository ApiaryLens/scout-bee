package main

import (
	"strings"
	"testing"
)

func validWindowsClientPlan() plan {
	p := validPlan()
	p.Target = "windows-client"
	p.Cloudflare = nil
	p.WindowsClient = &windowsClient{Architecture: "x64"}
	return p
}

func TestWindowsClientTargetIsDisabledByDefault(t *testing.T) {
	t.Setenv(windowsClientFlagEnvironment, "")
	if windowsClientEnabled() {
		t.Fatal("the Windows client feature flag must default to off")
	}
	err := validate(validWindowsClientPlan())
	if err == nil || !strings.Contains(err.Error(), "disabled") {
		t.Fatalf("expected the windows-client target to be rejected while the flag is off, got: %v", err)
	}
	payload := statusPayload()
	if enabled, ok := payload["windowsClientEnabled"].(bool); !ok || enabled {
		t.Fatalf("status must report windowsClientEnabled=false by default, got: %v", payload["windowsClientEnabled"])
	}
}

func TestWindowsClientTargetIgnoresNonAffirmativeFlagValues(t *testing.T) {
	for _, value := range []string{"0", "false", "yes", "on", "enable"} {
		t.Setenv(windowsClientFlagEnvironment, value)
		if windowsClientEnabled() {
			t.Fatalf("flag value %q must not enable the Windows client target", value)
		}
		if err := validate(validWindowsClientPlan()); err == nil {
			t.Fatalf("flag value %q unexpectedly allowed a windows-client plan", value)
		}
	}
}

func TestWindowsClientTargetRequiresExplicitFlag(t *testing.T) {
	for _, value := range []string{"1", "true", "TRUE", " 1 "} {
		t.Setenv(windowsClientFlagEnvironment, value)
		if !windowsClientEnabled() {
			t.Fatalf("flag value %q should enable the Windows client target", value)
		}
		if err := validate(validWindowsClientPlan()); err != nil {
			t.Fatalf("flag value %q should allow a valid windows-client plan, got: %v", value, err)
		}
		payload := statusPayload()
		if enabled, ok := payload["windowsClientEnabled"].(bool); !ok || !enabled {
			t.Fatalf("status must report windowsClientEnabled=true when the flag is set, got: %v", payload["windowsClientEnabled"])
		}
	}
}
