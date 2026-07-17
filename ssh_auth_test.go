package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestSSHAgentAuthenticationIsNonInteractiveAndRejectsMixedCredentials(t *testing.T) {
	input := request{Secrets: map[string]string{sshAuthMethodSecret: "agent"}}
	auth, err := prepareSSHRuntimeAuth(input)
	if err != nil {
		t.Fatal(err)
	}
	defer auth.cleanup()
	joined := strings.Join(auth.options, " ")
	if !strings.Contains(joined, "BatchMode=yes") || !strings.Contains(joined, "IdentitiesOnly=no") || len(auth.environment) != 0 {
		t.Fatalf("agent authentication was not noninteractive: %+v", auth)
	}
	input.Secrets[sshPasswordSecret] = "must-not-be-accepted"
	if _, err = prepareSSHRuntimeAuth(input); err == nil || !strings.Contains(err.Error(), "cannot include") {
		t.Fatalf("mixed agent/password authentication did not fail closed: %v", err)
	}
}

func TestSSHPrivateKeyUsesRuntimeOnlyAbsoluteRegularFile(t *testing.T) {
	keyPath := filepath.Join(t.TempDir(), "id_ed25519")
	if err := os.WriteFile(keyPath, []byte("synthetic-test-key"), 0o600); err != nil {
		t.Fatal(err)
	}
	input := request{Plan: validPlan(), Secrets: map[string]string{
		sshAuthMethodSecret: "private-key", sshPrivateKeyPathSecret: keyPath,
	}}
	auth, err := prepareSSHRuntimeAuth(input)
	if err != nil {
		t.Fatal(err)
	}
	defer auth.cleanup()
	joined := strings.Join(auth.options, " ")
	if !strings.Contains(joined, "-i "+keyPath) || !strings.Contains(joined, "IdentitiesOnly=yes") || !strings.Contains(joined, "BatchMode=yes") {
		t.Fatalf("private-key arguments were incomplete: %s", joined)
	}
	rawPlan, _ := json.Marshal(input.Plan)
	if bytes.Contains(rawPlan, []byte(keyPath)) || bytes.Contains(rawPlan, []byte("private-key")) {
		t.Fatalf("runtime SSH selection entered the deployment plan: %s", rawPlan)
	}
	input.Secrets[sshPrivateKeyPathSecret] = "relative-key"
	if _, err = prepareSSHRuntimeAuth(input); err == nil || !strings.Contains(err.Error(), "absolute") {
		t.Fatalf("relative private-key path did not fail closed: %v", err)
	}
	input.Secrets[sshPrivateKeyPathSecret] = t.TempDir()
	if _, err = prepareSSHRuntimeAuth(input); err == nil || !strings.Contains(err.Error(), "regular file") {
		t.Fatalf("directory private-key path did not fail closed: %v", err)
	}
}

func TestSSHAskpassUsesProtectedTemporaryFileAndCleansUp(t *testing.T) {
	input := request{Secrets: map[string]string{
		sshAuthMethodSecret: "password", sshPasswordSecret: "special & runtime-only ! password",
	}}
	auth, err := prepareSSHRuntimeAuth(input)
	if runtime.GOOS != "windows" {
		if err == nil || !strings.Contains(err.Error(), "packaged Windows Scout Bee") {
			t.Fatalf("non-Windows password authentication did not fail closed precisely: %v", err)
		}
		return
	}
	if err != nil {
		t.Fatal(err)
	}
	secretPath := auth.environment[sshAskpassFileEnvironment]
	if secretPath == "" || auth.environment["SSH_ASKPASS"] == "" || auth.environment["SSH_ASKPASS_REQUIRE"] != "force" {
		t.Fatalf("askpass environment was incomplete: %+v", auth.environment)
	}
	if strings.Contains(strings.Join(auth.options, " "), input.Secrets[sshPasswordSecret]) {
		t.Fatal("password entered OpenSSH arguments")
	}
	for _, value := range auth.environment {
		if value == input.Secrets[sshPasswordSecret] {
			t.Fatal("password entered OpenSSH environment")
		}
	}
	info, statErr := os.Stat(secretPath)
	if statErr != nil || !info.Mode().IsRegular() {
		t.Fatalf("protected askpass credential is unavailable: %v", statErr)
	}
	t.Setenv(sshAskpassFileEnvironment, secretPath)
	var output bytes.Buffer
	handled, exitCode := runSSHAskpass(&output)
	if !handled || exitCode != 0 || strings.TrimSuffix(output.String(), "\n") != input.Secrets[sshPasswordSecret] {
		t.Fatalf("askpass helper failed: handled=%v exit=%d output=%q", handled, exitCode, output.String())
	}
	auth.cleanup()
	if _, statErr = os.Stat(secretPath); !os.IsNotExist(statErr) {
		t.Fatalf("temporary askpass credential survived cleanup: %v", statErr)
	}
}

func TestSSHAskpassRejectsUnsupportedSecretsAndUntrustedPaths(t *testing.T) {
	for _, value := range []string{"", "line1\nline2", "nul\x00value"} {
		if err := validateAskpassSecret(value); err == nil {
			t.Fatalf("unsupported askpass value %q was accepted", value)
		}
	}
	untrusted := filepath.Join(t.TempDir(), "credential")
	if err := os.WriteFile(untrusted, []byte("not-readable-through-helper"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv(sshAskpassFileEnvironment, untrusted)
	var output bytes.Buffer
	handled, exitCode := runSSHAskpass(&output)
	if !handled || exitCode == 0 || output.Len() != 0 {
		t.Fatalf("untrusted askpass path was accepted: handled=%v exit=%d output=%q", handled, exitCode, output.String())
	}
}

func TestMergedEnvironmentReplacesCredentialBoundaryCaseInsensitively(t *testing.T) {
	merged := mergedEnvironment([]string{"Path=base", "SSH_ASKPASS=untrusted", "DISPLAY=old"}, map[string]string{
		"ssh_askpass": "trusted", "DISPLAY": "ApiaryLens",
	})
	joined := strings.Join(merged, "\n")
	if strings.Contains(joined, "untrusted") || strings.Contains(joined, "DISPLAY=old") || !strings.Contains(joined, "ssh_askpass=trusted") || !strings.Contains(joined, "DISPLAY=ApiaryLens") {
		t.Fatalf("environment override was ambiguous: %s", joined)
	}
}

func TestComposePreflightDoesNotPersistRuntimeSSHCredentialOrPath(t *testing.T) {
	runner, p := composePreflightFixture(t, false)
	secrets := map[string]string{"bootstrapToken": "owner-setup-code-long-enough", sshAuthMethodSecret: "agent"}
	adapter := &composeAdapter{executor: &executor{runner: runner}}
	phases, err := adapter.preflight(t.Context(), request{Plan: p, Secrets: secrets})
	if err != nil {
		t.Fatal(err)
	}
	rawPlan, _ := json.Marshal(p)
	rawPhases, _ := json.Marshal(phases)
	for _, forbidden := range []string{sshAuthMethodSecret, "owner-setup-code-long-enough"} {
		if bytes.Contains(rawPlan, []byte(forbidden)) || bytes.Contains(rawPhases, []byte(forbidden)) {
			t.Fatalf("runtime SSH input entered plan or phase evidence: %q", forbidden)
		}
	}
}
