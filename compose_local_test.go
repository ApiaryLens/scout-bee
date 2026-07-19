package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func validLocalPlan() plan {
	p := validPlan()
	p.Target = "compose-local"
	p.Cloudflare = nil
	p.LocalCompose = &localCompose{InstallDirectory: "/opt/apiarylens", ProjectName: "apiarylens-family", HTTPPort: 8420}
	return p
}

func TestValidateLocalComposePlan(t *testing.T) {
	if err := validate(validLocalPlan()); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*plan){
		"missing local target":  func(p *plan) { p.LocalCompose = nil },
		"extra cloud target":    func(p *plan) { p.Cloudflare = &cloudflare{} },
		"root install folder":   func(p *plan) { p.LocalCompose.InstallDirectory = "/" },
		"traversal folder":      func(p *plan) { p.LocalCompose.InstallDirectory = "/opt/../etc" },
		"relative folder":       func(p *plan) { p.LocalCompose.InstallDirectory = "opt/apiarylens" },
		"invalid project name":  func(p *plan) { p.LocalCompose.ProjectName = "Bad Name!" },
		"invalid http port":     func(p *plan) { p.LocalCompose.HTTPPort = 0 },
		"port above valid span": func(p *plan) { p.LocalCompose.HTTPPort = 70000 },
	} {
		p := validLocalPlan()
		mutate(&p)
		if err := validate(p); err == nil {
			t.Fatalf("%s must be rejected", name)
		}
	}
}

type missingShellRunner struct{}

func (missingShellRunner) Find(string) error { return errors.New("not found") }
func (missingShellRunner) Run(context.Context, command, map[string]string) (string, error) {
	return "", errors.New("must not run")
}

func TestMissingOwnerSetupCodeSaysWhereToFixIt(t *testing.T) {
	adapters := map[string]targetAdapter{
		"compose-local": &localComposeAdapter{executor: &executor{runner: &localLifecycleRunner{}}},
		"compose-ssh":   &composeAdapter{executor: &executor{runner: &localLifecycleRunner{}}},
	}
	plans := map[string]plan{"compose-local": validLocalPlan(), "compose-ssh": func() plan {
		p := validPlan()
		p.Target = "compose-ssh"
		p.Cloudflare = nil
		p.Compose = &compose{PublicURL: "https://hives.example", TargetDirectory: "/opt/apiarylens", SSHHostKeySha256: "SHA256:abc"}
		return p
	}()}
	for name, adapter := range adapters {
		phases, err := adapter.preflight(context.Background(), request{Plan: plans[name], Secrets: map[string]string{}})
		if err == nil || !strings.Contains(err.Error(), "Review step") || !strings.Contains(err.Error(), "first family owner") {
			t.Fatalf("%s owner-code failure must say where and why to fix it, err=%v phases=%+v", name, err, phases)
		}
	}
}

func TestLocalComposePreflightGivesHonestDockerGuidance(t *testing.T) {
	adapter := &localComposeAdapter{executor: &executor{runner: missingShellRunner{}}}
	phases, err := adapter.preflight(context.Background(), request{
		Plan: validLocalPlan(), Secrets: map[string]string{"bootstrapToken": "owner-setup-code-long-enough"},
	})
	if err == nil || len(phases) != 1 || phases[0].State != "failed" ||
		!strings.Contains(err.Error(), "Docker") {
		t.Fatalf("expected honest Docker guidance, err=%v phases=%+v", err, phases)
	}
}

type localLifecycleRunner struct {
	commands    []command
	dockerProbe string
}

func (f *localLifecycleRunner) Find(tool string) error {
	if tool != "wsl" && tool != "sh" {
		return fmt.Errorf("unexpected local tool %q", tool)
	}
	return nil
}

func (f *localLifecycleRunner) Run(_ context.Context, spec command, _ map[string]string) (string, error) {
	f.commands = append(f.commands, spec)
	joined := strings.Join(spec.Args, " ")
	switch {
	case strings.Contains(joined, "wslpath"):
		return "/mnt/c/translated/" + strings.ReplaceAll(spec.Args[len(spec.Args)-1], "\\", "/"), nil
	case bytes.Equal(spec.Stdin, []byte(localDockerProbeScript)):
		if f.dockerProbe != "" {
			return f.dockerProbe, nil
		}
		return "x86_64\nDocker Compose version v2.40.3\n", nil
	case bytes.Equal(spec.Stdin, []byte(composeTargetPreflightScript)):
		return "", nil
	case bytes.Equal(spec.Stdin, []byte(composeRemoteScript)):
		return "ApiaryLens 0.1.0-preview.1 is active and Docker health checks passed.\n", nil
	default:
		return "", nil
	}
}

func TestLocalComposePreflightReportsDockerAndFolderReadiness(t *testing.T) {
	runner := &localLifecycleRunner{}
	adapter := &localComposeAdapter{executor: &executor{runner: runner}}
	phases, err := adapter.preflight(context.Background(), request{
		Plan: validLocalPlan(), Secrets: map[string]string{"bootstrapToken": "owner-setup-code-long-enough"},
	})
	if err != nil || len(phases) != 3 {
		t.Fatalf("expected three passing local preflight phases, err=%v phases=%+v", err, phases)
	}
	if !strings.Contains(phases[2].Detail, "http://localhost:8420") || !strings.Contains(phases[2].Detail, "this computer only") {
		t.Fatalf("local-only exposure phase must state the honest localhost boundary: %+v", phases[2])
	}
}

func TestLocalComposeApplyRunsPinnedLifecycleThroughLocalShell(t *testing.T) {
	bundle := []byte("verified compose release bundle")
	bundleDigest := sha256.Sum256(bundle)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/bundle.tar.gz":
			_, _ = w.Write(bundle)
		case r.URL.Path == "/health":
			_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok", "product": "ApiaryLens", "version": "0.1.0-preview.1"})
		case strings.HasPrefix(r.URL.Path, "/attestations/"):
			_, _ = w.Write(testAttestationJSON(t, officialProductRepositoryURL, officialProductRepositoryURL, manifestArtifact{Name: "bundle.tar.gz", Sha256: hex.EncodeToString(bundleDigest[:])}))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	manifest := releaseManifest{
		Product: "ApiaryLens", ProductVersion: "0.1.0-preview.1", Channel: "preview",
		Artifacts: []manifestArtifact{{
			Name: "bundle.tar.gz", Kind: "deployment-bundle", Target: "compose",
			URL: server.URL + "/bundle.tar.gz", Sha256: hex.EncodeToString(bundleDigest[:]), Bytes: int64(len(bundle)),
		}},
	}
	runner := &localLifecycleRunner{}
	adapter := &localComposeAdapter{
		executor:      &executor{runner: runner, client: server.Client(), cacheDirectory: t.TempDir(), attestationURL: server.URL + "/attestations"},
		healthAddress: server.URL + "/health",
	}
	secrets := map[string]string{"bootstrapToken": "runtime-only-owner-setup-code"}
	phases, err := adapter.apply(context.Background(), request{Plan: validLocalPlan(), Mode: "apply", Secrets: secrets}, manifest)
	if err != nil || len(phases) != 6 {
		t.Fatalf("local apply failed: err=%v phases=%+v", err, phases)
	}
	expectedShell := localShellName()
	lifecycleRuns := 0
	for _, current := range runner.commands {
		if current.Executable != expectedShell {
			t.Fatalf("local lifecycle invoked unexpected executable %q", current.Executable)
		}
		joined := strings.Join(current.Args, " ")
		if strings.Contains(joined, secrets["bootstrapToken"]) || strings.Contains(joined, secrets["authRootSecret"]) {
			t.Fatalf("runtime secret leaked into process arguments: %s", joined)
		}
		if bytes.Equal(current.Stdin, []byte(composeRemoteScript)) {
			lifecycleRuns++
			if !strings.Contains(joined, "sh -s -- install ") {
				t.Fatalf("lifecycle script was not driven with the install operation: %s", joined)
			}
			if current.Args[len(current.Args)-1] != "8420" {
				t.Fatalf("local HTTP port was not passed as the final script argument: %s", joined)
			}
			if !strings.Contains(joined, base64.RawURLEncoding.EncodeToString([]byte("http://localhost"))) {
				t.Fatalf("local trial must target plain-HTTP localhost: %s", joined)
			}
		}
	}
	if lifecycleRuns != 1 {
		t.Fatalf("expected exactly one lifecycle script run, got %d", lifecycleRuns)
	}
}

func TestComposeLifecycleScriptSupportsOptionalLocalHTTPPort(t *testing.T) {
	for _, required := range []string{
		`http_port=${15:-}`,
		`if [ -n "$http_port" ]; then printf 'APIARYLENS_HTTP_PORT=%s\n' "$http_port" >> "$release_dir/docker/.env"; fi`,
	} {
		if !strings.Contains(composeRemoteScript, required) {
			t.Fatalf("Compose lifecycle script is missing %q", required)
		}
	}
}
