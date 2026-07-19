package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
)

// localComposeAdapter runs the released Compose bundle on this computer for
// the owner-directed "on this local machine" trial path (2026-07-19). It
// streams the exact lifecycle script used for compose-ssh into a local POSIX
// shell — WSL2 on Windows (Docker Desktop integration or Docker inside WSL),
// sh with Docker elsewhere — so the executed bytes and lifecycle semantics
// are identical to a server install. The trial serves plain HTTP on
// localhost only, produces no connection profile, and presents no connected
// options (design v2 §1c).
type localComposeAdapter struct {
	executor *executor
	// healthAddress overrides the derived http://localhost:<port> health
	// endpoint in tests.
	healthAddress string
}

// localShellCommand wraps a POSIX shell invocation for this machine.
func localShellCommand(shellArgs ...string) command {
	if runtime.GOOS == "windows" {
		return command{Executable: "wsl", Args: append([]string{"-e"}, shellArgs...)}
	}
	return command{Executable: shellArgs[0], Args: shellArgs[1:]}
}

func localShellName() string {
	if runtime.GOOS == "windows" {
		return "wsl"
	}
	return "sh"
}

const localDockerProbeScript = "set -eu\ncommand -v docker >/dev/null\ndocker compose version\nuname -m\ndate -u +%s\n"

func localDockerGuidance() string {
	if runtime.GOOS == "windows" {
		return "the local trial needs WSL2 with Docker: install Docker Desktop and enable its WSL integration (or install Docker inside your WSL distribution), then retry"
	}
	return "the local trial needs Docker with the Compose plugin: install Docker Engine and docker compose v2, then retry"
}

func (a *localComposeAdapter) preflight(ctx context.Context, input request) ([]phase, error) {
	if input.Plan.Operation == "install" && len(input.Secrets["bootstrapToken"]) < 16 {
		err := errors.New("installing needs a one-time owner setup code of at least 16 characters — go back to the Review step and enter one; Scout uses it once to protect who becomes the first family owner")
		return []phase{failed("Verify one-time owner setup protection", err)}, err
	}
	if err := a.executor.runner.Find(localShellName()); err != nil {
		err = fmt.Errorf("%s", localDockerGuidance())
		return []phase{failed("Find local container tools", err)}, err
	}
	probe := localShellCommand("sh", "-s")
	probe.Stdin = []byte(localDockerProbeScript)
	output, err := a.executor.runner.Run(ctx, probe, input.Secrets)
	if err != nil || !strings.Contains(output, "Docker Compose version") {
		err = fmt.Errorf("%s", localDockerGuidance())
		return []phase{failed("Verify local Docker prerequisites", err)}, err
	}
	phases := []phase{pass("Verify local Docker prerequisites", "This computer reports a working shell, Docker Engine, and Compose v2.")}
	target := base64.RawURLEncoding.EncodeToString([]byte(input.Plan.LocalCompose.InstallDirectory))
	folderProbe := localShellCommand("sh", "-s", "--", target)
	folderProbe.Stdin = []byte(composeTargetPreflightScript)
	if _, err = a.executor.runner.Run(ctx, folderProbe, input.Secrets); err != nil {
		err = errors.New("the install folder is not writable here; choose a folder your local (WSL) user can create, for example /home/<you>/apiarylens")
		return append(phases, failed("Verify install folder access", err)), err
	}
	phases = append(phases,
		pass("Verify install folder access", "The chosen folder is writable or can be created by your local user."),
		pass("Verify local-only exposure", fmt.Sprintf("The trial serves plain HTTP at http://localhost:%d on this computer only; nothing is published to the network and no connected options are offered.", input.Plan.LocalCompose.HTTPPort)),
	)
	return phases, nil
}

// localShellPath translates a host path into the local shell's view of the
// filesystem: on Windows the WSL /mnt/... path, elsewhere the path itself.
func (a *localComposeAdapter) localShellPath(ctx context.Context, hostPath string, secrets map[string]string) (string, error) {
	if runtime.GOOS != "windows" {
		return hostPath, nil
	}
	translate := localShellCommand("wslpath", "-a", "-u", hostPath)
	output, err := a.executor.runner.Run(ctx, translate, secrets)
	if err != nil {
		return "", fmt.Errorf("could not translate a Windows path for WSL: %w", err)
	}
	translated := strings.TrimSpace(output)
	if translated == "" || !strings.HasPrefix(translated, "/") {
		return "", errors.New("WSL returned an unusable path translation")
	}
	return translated, nil
}

func (a *localComposeAdapter) apply(ctx context.Context, input request, manifest releaseManifest) ([]phase, error) {
	local := input.Plan.LocalCompose
	phases := []phase{}
	bundleShellPath := ""
	bootstrapShellPath := ""
	authRootShellPath := ""
	if input.Plan.Operation == "install" || input.Plan.Operation == "update" || input.Plan.Operation == "repair" || input.Plan.Operation == "rollback" {
		artifact, artifactErr := artifactFor(manifest, "compose")
		if artifactErr != nil {
			return []phase{failed("Select verified Compose bundle", artifactErr)}, artifactErr
		}
		temp, tempErr := os.MkdirTemp("", "apiarylens-scout-local-")
		if tempErr != nil {
			return []phase{failed("Prepare protected staging folder", tempErr)}, tempErr
		}
		defer os.RemoveAll(temp)
		bundle, downloadErr := a.executor.downloadVerifiedArtifact(ctx, manifest, artifact, temp)
		if downloadErr != nil {
			return []phase{failed("Download and verify deployment bundle", downloadErr)}, downloadErr
		}
		phases = append(phases, pass("Download and verify deployment bundle", fmt.Sprintf("The immutable Compose bundle matches the release manifest: SHA-256 %s (%d bytes).", strings.ToLower(artifact.Sha256), artifact.Bytes)))
		attestationDetail, attestationErr := a.executor.verifyArtifactAttestation(ctx, artifact)
		if attestationErr != nil {
			return append(phases, failed("Verify GitHub build attestation", attestationErr)), attestationErr
		}
		phases = append(phases, pass("Verify GitHub build attestation", attestationDetail))
		var pathErr error
		if bundleShellPath, pathErr = a.localShellPath(ctx, bundle, input.Secrets); pathErr != nil {
			return append(phases, failed("Stage bundle for the local shell", pathErr)), pathErr
		}
		if input.Plan.Operation == "install" {
			authRootBytes := make([]byte, 48)
			if _, secretErr := rand.Read(authRootBytes); secretErr != nil {
				return append(phases, failed("Prepare authentication root secret", secretErr)), secretErr
			}
			input.Secrets["authRootSecret"] = base64.RawURLEncoding.EncodeToString(authRootBytes)
			for _, runtimeSecret := range []struct {
				value, name, label string
				target             *string
			}{
				{input.Secrets["bootstrapToken"], "bootstrap", "one-time owner setup protection", &bootstrapShellPath},
				{input.Secrets["authRootSecret"], "auth-root", "authentication root secret", &authRootShellPath},
			} {
				hostPath := filepath.Join(temp, "runtime-"+runtimeSecret.name)
				if writeErr := os.WriteFile(hostPath, []byte(runtimeSecret.value), 0o600); writeErr != nil {
					return append(phases, failed("Prepare "+runtimeSecret.label, writeErr)), writeErr
				}
				translated, translateErr := a.localShellPath(ctx, hostPath, input.Secrets)
				if translateErr != nil {
					return append(phases, failed("Prepare "+runtimeSecret.label, translateErr)), translateErr
				}
				*runtimeSecret.target = translated
				phases = append(phases, pass("Prepare "+runtimeSecret.label, "The runtime-only secret was written to a protected temporary file and was not logged."))
			}
		}
	}

	publicURL := "http://localhost"
	lifecycle := localShellCommand("sh", "-s", "--",
		input.Plan.Operation,
		base64.RawURLEncoding.EncodeToString([]byte(local.InstallDirectory)),
		base64.RawURLEncoding.EncodeToString([]byte(local.ProjectName)),
		base64.RawURLEncoding.EncodeToString([]byte(publicURL)),
		base64.RawURLEncoding.EncodeToString([]byte(manifest.ProductVersion)),
		base64.RawURLEncoding.EncodeToString([]byte(bundleShellPath)),
		strconv.FormatBool(input.Plan.KeepDataOnUninstall),
		base64.RawURLEncoding.EncodeToString([]byte(bootstrapShellPath)),
		base64.RawURLEncoding.EncodeToString([]byte(authRootShellPath)),
		base64.RawURLEncoding.EncodeToString([]byte(manifest.SourceCommit)),
		base64.RawURLEncoding.EncodeToString([]byte(manifest.BuildTime)),
		base64.RawURLEncoding.EncodeToString([]byte("ApiaryLens@"+manifest.ProductVersion+"+"+shortCommit(manifest.SourceCommit))),
		strconv.Itoa(14),
		"true",
		strconv.Itoa(local.HTTPPort),
	)
	lifecycle.Stdin = []byte(composeRemoteScript)
	output, err := a.executor.runner.Run(ctx, lifecycle, input.Secrets)
	if err != nil {
		return append(phases, failed("Apply local Compose operation", err)), err
	}
	phases = append(phases, pass("Apply local Compose operation", strings.TrimSpace(output)))
	if input.Plan.Operation == "install" || input.Plan.Operation == "update" || input.Plan.Operation == "repair" || input.Plan.Operation == "rollback" {
		address := a.healthAddress
		if address == "" {
			address = fmt.Sprintf("http://localhost:%d/health", local.HTTPPort)
		}
		if err = (&cloudflareAdapter{executor: a.executor}).verifyHealth(ctx, address, manifest); err != nil {
			return append(phases, failed("Verify local trial health", err)), err
		}
		phases = append(phases, pass("Verify local trial health", "The local trial reports the expected ApiaryLens release at http://localhost on this computer."))
	}
	return phases, nil
}
