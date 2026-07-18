package main

import (
	"os"
	"strings"
)

// windowsClientFlagEnvironment gates Scout's Windows client lifecycle target.
//
// ADR 0023 (2026-07-18) ships Scout bootstrap-scoped: the windows-client
// adapter stays compiled and tested, but it is hidden from the guide UI and
// rejected by plan validation unless this environment variable is explicitly
// set to "1" or "true" before launching Scout. The flag defaults to off
// (WIN-031, plan v2 P1-4).
const windowsClientFlagEnvironment = "SCOUT_BEE_ENABLE_WINDOWS_CLIENT"

func windowsClientEnabled() bool {
	value := strings.TrimSpace(strings.ToLower(os.Getenv(windowsClientFlagEnvironment)))
	return value == "1" || value == "true"
}
