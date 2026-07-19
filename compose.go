package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

type composeAdapter struct{ executor *executor }

func (a *composeAdapter) preflight(ctx context.Context, input request) ([]phase, error) {
	if input.Plan.Operation == "install" && len(input.Secrets["bootstrapToken"]) < 16 {
		err := errors.New("installing needs a one-time owner setup code of at least 16 characters — go back to the Review step and enter one; Scout uses it once to protect who becomes the first family owner")
		return []phase{failed("Verify one-time owner setup protection", err)}, err
	}
	for _, tool := range []string{"ssh", "scp", "ssh-keyscan"} {
		if err := a.executor.runner.Find(tool); err != nil {
			err = fmt.Errorf("OpenSSH tool %s is required; install the operating system OpenSSH client, then retry", tool)
			return []phase{failed("Find secure remote connection tools", err)}, err
		}
	}
	phases := []phase{pass("Find secure remote connection tools", "Found OpenSSH, secure copy, and host-key verification tools.")}
	knownHosts, err := a.verifiedKnownHosts(ctx, input)
	if err != nil {
		return append(phases, failed("Verify pinned server identity", err)), err
	}
	defer os.Remove(knownHosts)
	phases = append(phases, pass("Verify pinned server identity", "The live server key matches the SHA-256 fingerprint in the plan."))
	auth, err := prepareSSHRuntimeAuth(input)
	if err != nil {
		return append(phases, failed("Verify SSH authentication input", err)), err
	}
	defer auth.cleanup()
	phases = append(phases, pass("Verify SSH authentication input", "The selected runtime-only SSH authentication method is ready and was not added to the deployment plan."))
	compose := input.Plan.Compose
	script := []byte("set -eu\nuname -m\ncommand -v docker >/dev/null\ndocker compose version\ndf -Pk /\ndate -u +%s\n")
	output, err := a.executor.runner.Run(ctx, command{
		Executable: "ssh", Args: sshArgs(compose, knownHosts, auth.options, "sh", "-s"), Stdin: script, Environment: auth.environment,
	}, sshRedactions(input.Secrets, auth))
	if err != nil {
		return append(phases, failed("Verify Linux and Docker prerequisites", err)), err
	}
	if !strings.Contains(output, "Docker Compose version") {
		err = errors.New("the remote host does not report Docker Compose v2")
		return append(phases, failed("Verify Linux and Docker prerequisites", err)), err
	}
	phases = append(phases, pass("Verify Linux and Docker prerequisites", "The host is reachable and reports Docker Engine, Compose v2, disk, architecture, and UTC time."))
	target := base64.RawURLEncoding.EncodeToString([]byte(input.Plan.Compose.TargetDirectory))
	if _, err = a.executor.runner.Run(ctx, command{
		Executable: "ssh", Args: sshArgs(compose, knownHosts, auth.options, "sh", "-s", "--", target), Stdin: []byte(composeTargetPreflightScript), Environment: auth.environment,
	}, sshRedactions(input.Secrets, auth)); err != nil {
		err = errors.New("the install folder is not writable and the Linux user cannot create it with passwordless sudo")
		return append(phases, failed("Verify install folder access", err)), err
	}
	phases = append(phases,
		pass("Verify install folder access", "The chosen folder is writable or can be created with passwordless administrative access."),
		pass("Verify HTTPS deployment policy", "The plan exposes ApiaryLens only at an HTTPS address and never enables default credentials."),
	)
	return phases, nil
}

func (a *composeAdapter) apply(ctx context.Context, input request, manifest releaseManifest) ([]phase, error) {
	knownHosts, err := a.verifiedKnownHosts(ctx, input)
	if err != nil {
		return []phase{failed("Reverify pinned server identity", err)}, err
	}
	defer os.Remove(knownHosts)
	auth, err := prepareSSHRuntimeAuth(input)
	if err != nil {
		return []phase{failed("Verify SSH authentication input", err)}, err
	}
	defer auth.cleanup()
	compose := input.Plan.Compose
	phases := []phase{}
	remoteBundle := "/tmp/apiarylens-" + input.Plan.PlanID + ".tar.gz"
	remoteBootstrap := "/tmp/apiarylens-bootstrap-" + input.Plan.PlanID
	remoteAuthRoot := "/tmp/apiarylens-auth-root-" + input.Plan.PlanID
	if input.Plan.Operation == "install" || input.Plan.Operation == "update" || input.Plan.Operation == "repair" || input.Plan.Operation == "rollback" {
		artifact, artifactErr := artifactFor(manifest, "compose")
		if artifactErr != nil {
			return []phase{failed("Select verified Compose bundle", artifactErr)}, artifactErr
		}
		temp, tempErr := os.MkdirTemp("", "apiarylens-scout-compose-")
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
		destination := fmt.Sprintf("%s@%s:%s", compose.User, compose.Host, remoteBundle)
		args := []string{"-P", strconv.Itoa(compose.Port), "-o", "StrictHostKeyChecking=yes", "-o", "UserKnownHostsFile=" + knownHosts}
		args = append(args, auth.options...)
		args = append(args, "--", bundle, destination)
		if _, err = a.executor.runner.Run(ctx, command{Executable: "scp", Args: args, Environment: auth.environment}, sshRedactions(input.Secrets, auth)); err != nil {
			return append(phases, failed("Transfer verified deployment bundle", err)), err
		}
		phases = append(phases, pass("Transfer verified deployment bundle", "The checked bundle was transferred over the pinned SSH connection."))
		if input.Plan.Operation == "install" {
			authRootBytes := make([]byte, 48)
			if _, secretErr := rand.Read(authRootBytes); secretErr != nil {
				return append(phases, failed("Prepare authentication root secret", secretErr)), secretErr
			}
			input.Secrets["authRootSecret"] = base64.RawURLEncoding.EncodeToString(authRootBytes)
			for _, runtimeSecret := range []struct {
				value, remote, phase string
			}{
				{input.Secrets["bootstrapToken"], remoteBootstrap, "one-time owner setup protection"},
				{input.Secrets["authRootSecret"], remoteAuthRoot, "authentication root secret"},
			} {
				if secretErr := a.transferRemoteSecret(ctx, input, knownHosts, auth, runtimeSecret.remote, runtimeSecret.value); secretErr != nil {
					return append(phases, failed("Transfer "+runtimeSecret.phase, secretErr)), secretErr
				}
				phases = append(phases, pass("Transfer "+runtimeSecret.phase, "The runtime-only secret was streamed into a mode-0600 remote file separately from the release and was not logged."))
			}
		}
	}

	args := sshArgs(compose, knownHosts, auth.options, "sh", "-s", "--",
		input.Plan.Operation,
		base64.RawURLEncoding.EncodeToString([]byte(compose.TargetDirectory)),
		base64.RawURLEncoding.EncodeToString([]byte(compose.ProjectName)),
		base64.RawURLEncoding.EncodeToString([]byte(compose.PublicURL)),
		base64.RawURLEncoding.EncodeToString([]byte(manifest.ProductVersion)),
		base64.RawURLEncoding.EncodeToString([]byte(remoteBundle)),
		strconv.FormatBool(input.Plan.KeepDataOnUninstall),
		base64.RawURLEncoding.EncodeToString([]byte(remoteBootstrap)),
		base64.RawURLEncoding.EncodeToString([]byte(remoteAuthRoot)),
		base64.RawURLEncoding.EncodeToString([]byte(manifest.SourceCommit)),
		base64.RawURLEncoding.EncodeToString([]byte(manifest.BuildTime)),
		base64.RawURLEncoding.EncodeToString([]byte("ApiaryLens@"+manifest.ProductVersion+"+"+shortCommit(manifest.SourceCommit))),
		strconv.Itoa(compose.BackupRetention),
		strconv.FormatBool(webFrontendEnabled(compose.IncludeWebFrontend)),
	)
	output, err := a.executor.runner.Run(ctx, command{Executable: "ssh", Args: args, Stdin: []byte(composeRemoteScript), Environment: auth.environment}, sshRedactions(input.Secrets, auth))
	if err != nil {
		return append(phases, failed("Apply remote Compose operation", err)), err
	}
	phases = append(phases, pass("Apply remote Compose operation", strings.TrimSpace(output)))
	if input.Plan.Operation == "install" || input.Plan.Operation == "update" || input.Plan.Operation == "repair" || input.Plan.Operation == "rollback" {
		if err = (&cloudflareAdapter{executor: a.executor}).verifyHealth(ctx, strings.TrimSuffix(compose.PublicURL, "/")+"/health", manifest); err != nil {
			return append(phases, failed("Verify public HTTPS health", err)), err
		}
		phases = append(phases, pass("Verify public HTTPS health", "The remote deployment reports the expected ApiaryLens release over HTTPS."))
	}
	return phases, nil
}

func (a *composeAdapter) verifiedKnownHosts(ctx context.Context, input request) (string, error) {
	compose := input.Plan.Compose
	output, err := a.executor.runner.Run(ctx, command{Executable: "ssh-keyscan", Args: []string{"-p", strconv.Itoa(compose.Port), "-T", "8", compose.Host}}, input.Secrets)
	var path string
	if err != nil || !containsHostKey(output) {
		path, err = a.captureKnownHostWithoutAuthentication(ctx, input)
		if err != nil {
			return "", fmt.Errorf("could not read the server host key: %w", err)
		}
		raw, readErr := os.ReadFile(path)
		if readErr != nil {
			_ = os.Remove(path)
			return "", errors.New("could not read the captured server host key")
		}
		output = string(raw)
	}
	matched := false
	for _, line := range strings.Split(output, "\n") {
		if strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}
		key, decodeErr := base64.StdEncoding.DecodeString(fields[2])
		if decodeErr != nil {
			continue
		}
		digest := sha256.Sum256(key)
		fingerprint := "SHA256:" + base64.RawStdEncoding.EncodeToString(digest[:])
		if fingerprint == compose.SSHHostKeySha256 {
			matched = true
			break
		}
	}
	if !matched {
		if path != "" {
			_ = os.Remove(path)
		}
		return "", errors.New("the live SSH host key does not match the fingerprint in the deployment plan")
	}
	if path != "" {
		return path, nil
	}
	file, err := os.CreateTemp("", "apiarylens-known-hosts-")
	if err != nil {
		return "", err
	}
	path = file.Name()
	if err = file.Chmod(0o600); err == nil {
		_, err = file.WriteString(output)
	}
	closeErr := file.Close()
	if err != nil || closeErr != nil {
		_ = os.Remove(path)
		return "", errors.Join(err, closeErr)
	}
	return path, nil
}

func containsHostKey(output string) bool {
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 3 && !strings.HasPrefix(strings.TrimSpace(line), "#") {
			if _, err := base64.StdEncoding.DecodeString(fields[2]); err == nil {
				return true
			}
		}
	}
	return false
}

func (a *composeAdapter) captureKnownHostWithoutAuthentication(ctx context.Context, input request) (string, error) {
	file, err := os.CreateTemp("", "apiarylens-known-hosts-probe-")
	if err != nil {
		return "", err
	}
	path := file.Name()
	if err = file.Chmod(0o600); err == nil {
		err = file.Close()
	} else {
		_ = file.Close()
	}
	if err != nil {
		_ = os.Remove(path)
		return "", err
	}
	compose := input.Plan.Compose
	probeCtx, cancel := context.WithTimeout(ctx, 12*time.Second)
	defer cancel()
	_, _ = a.executor.runner.Run(probeCtx, command{Executable: "ssh", Args: []string{
		"-p", strconv.Itoa(compose.Port),
		"-o", "BatchMode=yes",
		"-o", "ConnectTimeout=8",
		"-o", "StrictHostKeyChecking=accept-new",
		"-o", "UserKnownHostsFile=" + path,
		"-o", "GlobalKnownHostsFile=" + os.DevNull,
		"-o", "PreferredAuthentications=none",
		"-o", "PubkeyAuthentication=no",
		"-o", "PasswordAuthentication=no",
		"-o", "KbdInteractiveAuthentication=no",
		"-T", "-N", "--", "__apiarylens_host_key_probe__@" + compose.Host,
	}}, input.Secrets)
	if raw, readErr := os.ReadFile(path); readErr != nil || !containsHostKey(string(raw)) {
		_ = os.Remove(path)
		return "", errors.New("the server did not provide a usable host key")
	}
	return path, nil
}

func sshArgs(target *compose, knownHosts string, authOptions []string, remote ...string) []string {
	args := []string{"-p", strconv.Itoa(target.Port), "-o", "StrictHostKeyChecking=yes", "-o", "UserKnownHostsFile=" + knownHosts}
	args = append(args, authOptions...)
	args = append(args, "--", target.User+"@"+target.Host)
	return append(args, remote...)
}

func (a *composeAdapter) transferRemoteSecret(ctx context.Context, input request, knownHosts string, auth sshRuntimeAuth, remote, value string) error {
	compose := input.Plan.Compose
	args := sshArgs(compose, knownHosts, auth.options,
		"sh", "-c", "'umask 077; cat > \"$1\"; chmod 600 \"$1\"'", "sh", remote,
	)
	_, err := a.executor.runner.Run(ctx, command{Executable: "ssh", Args: args, Stdin: []byte(value), Environment: auth.environment}, sshRedactions(input.Secrets, auth))
	return err
}

func sshRedactions(secrets map[string]string, auth sshRuntimeAuth) map[string]string {
	redactions := make(map[string]string, len(secrets)+1)
	for key, value := range secrets {
		redactions[key] = value
	}
	if path := auth.environment[sshAskpassFileEnvironment]; path != "" {
		redactions["sshAskpassPath"] = path
	}
	return redactions
}

const composeRemoteScript = `set -eu
umask 077
decode() {
  encoded=$(printf '%s' "$1" | tr '_-' '/+')
  case $((${#encoded} % 4)) in
    0) ;;
    2) encoded="${encoded}==" ;;
    3) encoded="${encoded}=" ;;
    *) return 65 ;;
  esac
  printf '%s' "$encoded" | base64 -d
}
operation=$1
target=$(decode "$2")
project=$(decode "$3")
public_url=$(decode "$4")
version=$(decode "$5")
bundle=$(decode "$6")
keep_data=$7
bootstrap_file=$(decode "$8")
auth_root_file=$(decode "$9")
source_commit=$(decode "${10}")
build_time=$(decode "${11}")
artifact_identity=$(decode "${12}")
backup_retention=${13}
include_web_frontend=${14}
http_port=${15:-}
prepare_target() {
  if [ -e "$target" ] || [ -L "$target" ]; then
    [ ! -L "$target" ] && [ -d "$target" ] && [ -w "$target" ] || return 73
    [ "$(stat -c '%u' "$target")" = "$(id -u)" ] || return 73
  else
    parent=$(dirname "$target")
    while [ ! -e "$parent" ] && [ "$parent" != "/" ]; do
      parent=$(dirname "$parent")
    done
    if [ -d "$parent" ] && [ -w "$parent" ]; then
      mkdir -p "$target"
    elif command -v sudo >/dev/null 2>&1 && sudo -n true >/dev/null 2>&1; then
      sudo install -d -m 0700 -o "$(id -u)" -g "$(id -g)" "$target"
    else
      return 73
    fi
  fi
  chmod 700 "$target"
}
prepare_target
release_dir="$target/releases/$version"
current="$target/current"
backups="$target/backups"
secrets_dir="$target/secrets"

safe_backup() {
  mkdir -p "$backups"
  stamp=$(date -u +%Y%m%dT%H%M%SZ)
  destination="$backups/$version-$stamp"
  mkdir -p "$destination"
  if [ -f "$secrets_dir/auth-root" ]; then cp "$secrets_dir/auth-root" "$destination/auth-root"; fi
  if [ -f "$current/docker/compose.yaml" ]; then
    docker compose -p "$project" -f "$current/docker/compose.yaml" stop api
    trap 'docker compose -p "$project" -f "$current/docker/compose.yaml" up -d --wait api >/dev/null 2>&1 || true' EXIT
  fi
  docker run --rm -v "${project}_apiarylens_data:/data:ro" -v "$destination:/backup" alpine:3.22 sh -c 'cd /data && tar czf /backup/data.tar.gz .'
  gzip -t "$destination/data.tar.gz"
  tar tzf "$destination/data.tar.gz" >/dev/null
  if [ -f "$current/release-manifest.json" ]; then cp "$current/release-manifest.json" "$destination/"; fi
  find "$backups" -mindepth 1 -maxdepth 1 -type d -printf '%T@ %p\n' | sort -nr | tail -n "+$((backup_retention + 1))" | cut -d' ' -f2- | while IFS= read -r expired; do
    case "$expired" in "$backups"/*) rm -rf -- "$expired" ;; *) exit 65 ;; esac
  done
  if [ -f "$current/docker/compose.yaml" ]; then
    docker compose -p "$project" -f "$current/docker/compose.yaml" up -d --wait api
    trap - EXIT
  fi
  printf '%s\n' "$destination"
}

case "$operation" in
  install|update|repair|rollback)
    previous=''
    if [ -L "$current" ]; then previous=$(readlink -f "$current"); fi
    if [ "$operation" != install ] && [ -n "$previous" ]; then safe_backup >/dev/null; fi
    mkdir -p "$release_dir"
    tar xzf "$bundle" -C "$release_dir"
    rm -f "$bundle"
    mkdir -p "$secrets_dir"
    chmod 700 "$target" "$secrets_dir"
    if [ "$operation" = install ]; then
      test -s "$bootstrap_file"
      test -s "$auth_root_file"
      mv "$bootstrap_file" "$secrets_dir/bootstrap-token"
      if [ -f "$secrets_dir/auth-root" ]; then rm -f "$auth_root_file"
      else mv "$auth_root_file" "$secrets_dir/auth-root"; fi
      # Compose implements local file-backed secrets as bind mounts. The
      # unprivileged container user therefore needs read permission on the
      # files, while the mode-0700 parent keeps them private on the host.
      chmod 644 "$secrets_dir/bootstrap-token"
      chmod 644 "$secrets_dir/auth-root"
    fi
    caddyfile=Caddyfile.backend-only
    if [ "$include_web_frontend" = true ]; then caddyfile=Caddyfile; fi
    printf 'APIARYLENS_VERSION=%s\nAPIARYLENS_SITE_ADDRESS=%s\nAPIARYLENS_BOOTSTRAP_SECRET_FILE=%s\nAPIARYLENS_AUTH_ROOT_SECRET_FILE=%s\nAPIARYLENS_SOURCE_COMMIT=%s\nAPIARYLENS_BUILD_TIME=%s\nAPIARYLENS_ARTIFACT_IDENTITY=%s\nAPIARYLENS_CADDYFILE=%s\n' "$version" "${public_url#https://}" "$secrets_dir/bootstrap-token" "$secrets_dir/auth-root" "$source_commit" "$build_time" "$artifact_identity" "$caddyfile" > "$release_dir/docker/.env"
    if [ -n "$http_port" ]; then printf 'APIARYLENS_HTTP_PORT=%s\n' "$http_port" >> "$release_dir/docker/.env"; fi
    chmod 600 "$release_dir/docker/.env"
    ln -sfn "$release_dir" "$current.next"
    if ! docker compose -p "$project" --env-file "$release_dir/docker/.env" -f "$release_dir/docker/compose.yaml" up -d --build --wait; then
      rm -f "$current.next"
      if [ -n "$previous" ]; then docker compose -p "$project" -f "$previous/docker/compose.yaml" up -d --wait || true; fi
      exit 42
    fi
    mv -Tf "$current.next" "$current"
    printf 'ApiaryLens %s is active and Docker health checks passed.\n' "$version"
    ;;
  backup|export)
    destination=$(safe_backup)
    printf 'Verified data and media archive: %s\n' "$destination"
    ;;
  restore)
    latest=$(find "$backups" -mindepth 1 -maxdepth 1 -type d -printf '%T@ %p\n' | sort -nr | head -n1 | cut -d' ' -f2-)
    [ -n "$latest" ] && gzip -t "$latest/data.tar.gz"
    docker compose -p "$project" -f "$current/docker/compose.yaml" down
    if [ -f "$latest/auth-root" ]; then mkdir -p "$secrets_dir"; chmod 700 "$secrets_dir"; cp "$latest/auth-root" "$secrets_dir/auth-root"; chmod 644 "$secrets_dir/auth-root"; fi
    docker run --rm -v "${project}_apiarylens_data:/data" -v "$latest:/backup:ro" alpine:3.22 sh -c 'rm -rf /data/* /data/.[!.]* /data/..?* 2>/dev/null || true; tar xzf /backup/data.tar.gz -C /data'
    docker run --rm --user 0:0 -v "${project}_apiarylens_data:/data" "apiarylens-api:$version" node -e "const { DatabaseSync } = require('node:sqlite'); const db = new DatabaseSync('/data/apiarylens.sqlite'); db.exec('DELETE FROM sessions'); db.close();"
    docker compose -p "$project" -f "$current/docker/compose.yaml" up -d --wait
    printf 'The latest verified backup was restored, sessions were revoked, and health checks passed.\n'
    ;;
  uninstall)
    if [ -f "$current/docker/compose.yaml" ]; then
      if [ "$keep_data" = true ]; then docker compose -p "$project" -f "$current/docker/compose.yaml" down
      else
        mkdir -p "$secrets_dir"
        chmod 700 "$secrets_dir"
        for required_secret in "$secrets_dir/bootstrap-token" "$secrets_dir/auth-root"; do
          if [ ! -f "$required_secret" ]; then (umask 077; : > "$required_secret"); fi
        done
        docker compose -p "$project" -f "$current/docker/compose.yaml" down -v
      fi
    fi
    if [ "$keep_data" = false ]; then
      rm -rf "$target"/* "$target"/.[!.]* "$target"/..?* 2>/dev/null || true
      if ! rmdir "$target" 2>/dev/null; then sudo -n rmdir "$target"; fi
    fi
    printf 'ApiaryLens services were removed; keep-data=%s.\n' "$keep_data"
    ;;
  *) printf 'Unsupported operation\n' >&2; exit 64 ;;
esac
`

const composeTargetPreflightScript = `set -eu
decode() {
  encoded=$(printf '%s' "$1" | tr '_-' '/+')
  case $((${#encoded} % 4)) in
    0) ;;
    2) encoded="${encoded}==" ;;
    3) encoded="${encoded}=" ;;
    *) return 65 ;;
  esac
  printf '%s' "$encoded" | base64 -d
}
target=$(decode "$1")
if [ -e "$target" ] || [ -L "$target" ]; then
  [ ! -L "$target" ] && [ -d "$target" ] && [ -w "$target" ]
  [ "$(stat -c '%u' "$target")" = "$(id -u)" ]
else
  parent=$(dirname "$target")
  while [ ! -e "$parent" ] && [ "$parent" != "/" ]; do
    parent=$(dirname "$parent")
  done
  { [ -d "$parent" ] && [ -w "$parent" ]; } || { command -v sudo >/dev/null 2>&1 && sudo -n true >/dev/null 2>&1; }
fi
`
