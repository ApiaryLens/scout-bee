package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"
)

const windowsTarget = "windows-x64"

type windowsClientAdapter struct{ executor *executor }

type windowsLifecycleSystem interface {
	Supported() bool
	Paths(string) (windowsLifecyclePaths, error)
	VerifyAuthenticode(string, windowsPackageSignature) error
	Run(context.Context, string, []string) (string, error)
	HealthSmoke(context.Context, string) (windowsSmokeEvidence, error)
}

type windowsLifecyclePaths struct {
	InstallRoot string
	Updater     string
	Application string
}

type nativeWindowsLifecycle struct{}

type windowsClientState struct {
	SchemaVersion         int    `json:"schemaVersion"`
	Installed             bool   `json:"installed"`
	ProductVersion        string `json:"productVersion"`
	PackageManifestSha256 string `json:"packageManifestSha256"`
	SetupSha256           string `json:"setupSha256"`
	DataRetained          bool   `json:"dataRetained"`
}

type windowsSmokeEvidence struct {
	LoopbackOnly                bool     `json:"loopbackOnly"`
	UnauthorizedRequestRejected bool     `json:"unauthorizedRequestRejected"`
	AuthenticatedHealthPassed   bool     `json:"authenticatedHealthPassed"`
	ProductShellServed          bool     `json:"productShellServed"`
	SandboxedRenderer           bool     `json:"sandboxedRenderer"`
	BridgeKeys                  []string `json:"bridgeKeys"`
	ControlTokenExposed         bool     `json:"controlTokenExposedInRenderer"`
}

type windowsHeadlessRequest struct {
	SchemaVersion int                     `json:"schemaVersion"`
	Operation     string                  `json:"operation"`
	ArchivePath   string                  `json:"archivePath"`
	Expected      windowsHeadlessIdentity `json:"expected"`
}

type windowsHeadlessIdentity struct {
	ProductVersion    string `json:"productVersion"`
	DatabaseMigration string `json:"databaseMigration"`
}

type windowsHeadlessEvidence struct {
	SchemaVersion          int    `json:"schemaVersion"`
	Operation              string `json:"operation"`
	Status                 string `json:"status"`
	ProductVersion         string `json:"productVersion"`
	DatabaseMigration      string `json:"databaseMigration"`
	Files                  *int   `json:"files,omitempty"`
	SourceCreatedAt        string `json:"sourceCreatedAt,omitempty"`
	RecoveryBackupVerified *bool  `json:"recoveryBackupVerified,omitempty"`
	RollbackPerformed      *bool  `json:"rollbackPerformed,omitempty"`
	RollbackVerified       *bool  `json:"rollbackVerified,omitempty"`
	ErrorCode              string `json:"errorCode,omitempty"`
}

func (nativeWindowsLifecycle) Supported() bool { return runtime.GOOS == "windows" }

func (nativeWindowsLifecycle) Paths(expectedVersion string) (windowsLifecyclePaths, error) {
	root, err := os.UserCacheDir()
	if err != nil || root == "" {
		return windowsLifecyclePaths{}, errors.New("the current-user Windows application folder is unavailable")
	}
	return resolveInstalledWindowsPaths(filepath.Join(root, "ApiaryLens"), expectedVersion)
}

func resolveInstalledWindowsPaths(installRoot, expectedVersion string) (windowsLifecyclePaths, error) {
	if !compatibleProductVersion(expectedVersion) || !filepath.IsAbs(installRoot) {
		return windowsLifecyclePaths{}, errors.New("the expected Windows installation identity is invalid")
	}
	root, err := filepath.Abs(installRoot)
	if err != nil {
		return windowsLifecyclePaths{}, err
	}
	rootInfo, err := os.Lstat(root)
	if err != nil || !rootInfo.IsDir() || rootInfo.Mode()&os.ModeSymlink != 0 {
		return windowsLifecyclePaths{}, errors.New("the Windows installation root is missing or uses a reparse path")
	}
	canonicalRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		return windowsLifecyclePaths{}, errors.New("the Windows installation root is missing or uses a reparse path")
	}
	entries, err := os.ReadDir(canonicalRoot)
	if err != nil {
		return windowsLifecyclePaths{}, errors.New("the Windows installation folder is unreadable")
	}
	expectedName := "app-" + squirrelVersion(expectedVersion)
	var application string
	for _, entry := range entries {
		if !strings.HasPrefix(strings.ToLower(entry.Name()), "app-") {
			continue
		}
		if entry.Name() != expectedName || !entry.IsDir() || entry.Type()&os.ModeSymlink != 0 {
			continue
		}
		candidate := filepath.Join(canonicalRoot, entry.Name())
		resolved, resolveErr := filepath.EvalSymlinks(candidate)
		if resolveErr != nil || !sameWindowsPath(candidate, resolved) || !sameWindowsPath(filepath.Dir(resolved), canonicalRoot) {
			return windowsLifecyclePaths{}, errors.New("the selected Windows application folder uses an unsafe reparse path")
		}
		host := filepath.Join(resolved, "ApiaryLens.exe")
		hostInfo, statErr := os.Lstat(host)
		if statErr != nil || !hostInfo.Mode().IsRegular() || hostInfo.Mode()&os.ModeSymlink != 0 {
			return windowsLifecyclePaths{}, errors.New("the selected Windows application executable is missing or unsafe")
		}
		resolvedHost, resolveErr := filepath.EvalSymlinks(host)
		if resolveErr != nil || !sameWindowsPath(host, resolvedHost) {
			return windowsLifecyclePaths{}, errors.New("the selected Windows application executable uses a reparse path")
		}
		if application != "" {
			return windowsLifecyclePaths{}, errors.New("multiple matching Windows application folders were found")
		}
		application = resolvedHost
	}
	if application == "" {
		return windowsLifecyclePaths{}, errors.New("the expected installed Windows application version was not found")
	}
	updater := filepath.Join(canonicalRoot, "Update.exe")
	updaterInfo, err := os.Lstat(updater)
	if err != nil || !updaterInfo.Mode().IsRegular() || updaterInfo.Mode()&os.ModeSymlink != 0 {
		return windowsLifecyclePaths{}, errors.New("the Windows current-user updater is missing or unsafe")
	}
	resolvedUpdater, err := filepath.EvalSymlinks(updater)
	if err != nil || !sameWindowsPath(updater, resolvedUpdater) {
		return windowsLifecyclePaths{}, errors.New("the Windows current-user updater uses a reparse path")
	}
	return windowsLifecyclePaths{InstallRoot: canonicalRoot, Updater: resolvedUpdater, Application: application}, nil
}

func sameWindowsPath(left, right string) bool {
	return strings.EqualFold(filepath.Clean(left), filepath.Clean(right))
}

func (nativeWindowsLifecycle) VerifyAuthenticode(path string, signature windowsPackageSignature) error {
	if runtime.GOOS != "windows" {
		return errors.New("Authenticode verification requires Windows")
	}
	powerShell, err := exec.LookPath("powershell.exe")
	if err != nil {
		return errors.New("Windows PowerShell is required for Authenticode verification")
	}
	script := `$ErrorActionPreference='Stop'; $s=Get-AuthenticodeSignature -LiteralPath $args[0]; if ($s.Status -ne 'Valid') { exit 41 }; if ($s.SignerCertificate.Thumbprint -ne $args[1]) { exit 42 }; if ($s.SignerCertificate.Subject -ne $args[2]) { exit 43 }`
	command := exec.Command(powerShell, "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", script, path, signature.Thumbprint, signature.Publisher)
	command.Env = os.Environ()
	if output, runErr := command.CombinedOutput(); runErr != nil {
		_ = output // Authenticode output can contain local paths and is intentionally not retained.
		return errors.New("the Windows executable has an invalid or unexpected Authenticode signer")
	}
	return nil
}

func (nativeWindowsLifecycle) Run(ctx context.Context, executable string, args []string) (string, error) {
	if runtime.GOOS != "windows" || !filepath.IsAbs(executable) {
		return "", errors.New("the Windows lifecycle executable is unavailable or unsafe")
	}
	command := exec.CommandContext(ctx, executable, args...)
	command.Env = os.Environ()
	output, err := command.CombinedOutput()
	if len(output) > 32<<10 {
		output = output[len(output)-(32<<10):]
	}
	if err != nil {
		return "", fmt.Errorf("the Windows lifecycle command failed: %w", err)
	}
	return string(output), nil
}

func (nativeWindowsLifecycle) HealthSmoke(ctx context.Context, executable string) (windowsSmokeEvidence, error) {
	if runtime.GOOS != "windows" || !filepath.IsAbs(executable) {
		return windowsSmokeEvidence{}, errors.New("the installed Windows health check is unavailable or unsafe")
	}
	evidence, err := os.CreateTemp("", "apiarylens-windows-health-*.json")
	if err != nil {
		return windowsSmokeEvidence{}, err
	}
	evidencePath := evidence.Name()
	_ = evidence.Close()
	_ = os.Remove(evidencePath)
	defer os.Remove(evidencePath)
	command := exec.Command(executable, "--desktop-smoke="+evidencePath)
	command.Env = os.Environ()
	if err = command.Start(); err != nil {
		return windowsSmokeEvidence{}, err
	}
	waited := make(chan error, 1)
	go func() { waited <- command.Wait() }()
	processExited := false
	defer func() {
		if command.Process != nil && !processExited {
			taskkill, lookupErr := exec.LookPath("taskkill.exe")
			if lookupErr == nil {
				_ = exec.Command(taskkill, "/PID", strconv.Itoa(command.Process.Pid), "/T", "/F").Run()
			} else {
				_ = command.Process.Kill()
			}
		}
		if !processExited {
			select {
			case <-waited:
			case <-time.After(5 * time.Second):
			}
		}
	}()
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return windowsSmokeEvidence{}, errors.New("the installed Windows health check timed out")
		case err = <-waited:
			processExited = true
			return windowsSmokeEvidence{}, fmt.Errorf("the installed Windows host exited before health evidence: %w", err)
		case <-ticker.C:
			raw, readErr := os.ReadFile(evidencePath)
			if readErr != nil {
				continue
			}
			var result windowsSmokeEvidence
			if json.Unmarshal(raw, &result) == nil {
				return result, nil
			}
		}
	}
}

func (a *windowsClientAdapter) system() windowsLifecycleSystem {
	if a.executor.windows != nil {
		return a.executor.windows
	}
	return nativeWindowsLifecycle{}
}

func (a *windowsClientAdapter) preflight(_ context.Context, input request) ([]phase, error) {
	phases := []phase{pass("Validate Windows client lifecycle plan", "The plan selects the current-user x64 Windows client and contains no credentials or local user paths.")}
	if input.Plan.Operation == "export" {
		err := errors.New("the Windows client export operation is not implemented; Scout will not run Setup for this request")
		return append(phases, failed("Verify Windows lifecycle operation", err)), err
	}
	allowed := map[string]bool{"install": true, "update": true, "repair": true, "rollback": true, "backup": true, "restore": true, "uninstall": true}
	if !allowed[input.Plan.Operation] {
		err := errors.New("the Windows client lifecycle operation is unsupported")
		return append(phases, failed("Verify Windows lifecycle operation", err)), err
	}
	if (input.Plan.Operation == "backup" || input.Plan.Operation == "restore") && input.Mode != "dry-run" {
		if _, err := validateRuntimeArchivePath(input.Secrets["windowsArchivePath"], input.Plan.Operation); err != nil {
			return append(phases, failed("Validate runtime backup location", err)), err
		}
		phases = append(phases, pass("Validate runtime backup location", "The runtime-only archive location is absolute and was not added to the plan, state, logs, or diagnostics."))
	}
	if input.Plan.Operation == "uninstall" && !input.Plan.KeepDataOnUninstall {
		phases = append(phases, pass("Plan explicit permanent data removal", "The plan identifies application, database, original media, backups, logs, and protected credentials for permanent removal. No data has been deleted."))
		if input.Mode != "dry-run" {
			err := errors.New("permanent data deletion requires a separately confirmed removal operation; this lifecycle adapter will not infer consent")
			return append(phases, failed("Require permanent-delete confirmation", err)), err
		}
	}
	if input.Mode != "dry-run" && !a.system().Supported() {
		err := errors.New("Windows client lifecycle changes can be applied only from Scout Bee running on Windows")
		return append(phases, failed("Verify Windows execution environment", err)), err
	}
	return phases, nil
}

func (a *windowsClientAdapter) apply(ctx context.Context, input request, manifest releaseManifest) ([]phase, error) {
	packageArtifact, err := windowsPackageManifestArtifact(manifest.ProductVersion, input.Plan.WindowsClient.Architecture, manifest)
	if err != nil {
		return []phase{failed("Select Windows package manifest", err)}, err
	}
	packagePath, err := a.executor.downloadArtifact(ctx, packageArtifact, "")
	if err != nil {
		return []phase{failed("Download and verify Windows package manifest", err)}, err
	}
	packageManifest, err := readWindowsPackageManifest(packagePath, manifest, packageArtifact)
	if err != nil {
		return []phase{failed("Verify Windows package identity", err)}, err
	}
	unsignedPreview, err := validateWindowsPackageTrust(manifest, packageManifest)
	if err != nil {
		return []phase{failed("Verify Windows package trust", err)}, err
	}
	identityDetail := "The package manifest matches the pinned product release, architecture, source commit, package kind, size, checksum, and declared Authenticode signer."
	if unsignedPreview {
		identityDetail = "The package manifest matches the pinned product release and explicitly declares an unsigned Preview package with no signer identity."
	}
	phases := []phase{pass("Verify Windows package identity", identityDetail)}
	stateStore, err := a.newStateStore()
	if err != nil {
		return append(phases, failed("Open Windows lifecycle state", err)), err
	}
	state, stateErr := stateStore.load()
	if input.Plan.Operation != "install" && input.Plan.Operation != "uninstall" && (stateErr != nil || !state.Installed) {
		err = errors.New("the requested lifecycle operation requires a Scout-managed installed Windows client")
		return append(phases, failed("Verify installed Windows client state", err)), err
	}

	if input.Plan.Operation == "uninstall" {
		if stateErr == nil && state.Installed && state.ProductVersion != manifest.ProductVersion {
			err = errors.New("uninstall requires the exact installed product release so the updater trust policy can be verified")
			return append(phases, failed("Verify Windows lifecycle transition", err)), err
		}
		return a.uninstall(ctx, input, manifest, packageManifest, stateStore, state, phases)
	}
	if input.Plan.Operation == "backup" || input.Plan.Operation == "restore" {
		if state.ProductVersion != manifest.ProductVersion || !strings.EqualFold(state.PackageManifestSha256, packageArtifact.Sha256) || manifest.Contracts.DatabaseMigration == "" {
			err = errors.New("backup and restore require the exact Scout-managed installed product and database migration identity")
			return append(phases, failed("Verify installed backup compatibility", err)), err
		}
		return a.runHeadlessLifecycle(ctx, input, manifest, packageManifest, state, phases)
	}
	if input.Plan.Operation == "install" && stateErr == nil && state.Installed {
		err = errors.New("the Windows client is already installed; choose update or repair")
		return append(phases, failed("Verify Windows lifecycle transition", err)), err
	}
	if input.Plan.Operation == "update" && state.ProductVersion == manifest.ProductVersion {
		err = errors.New("the selected version is already installed; choose repair")
		return append(phases, failed("Verify Windows lifecycle transition", err)), err
	}
	if input.Plan.Operation == "repair" && state.ProductVersion != manifest.ProductVersion {
		err = errors.New("repair requires the installed release; choose update or rollback for another version")
		return append(phases, failed("Verify Windows lifecycle transition", err)), err
	}
	if input.Plan.Operation == "rollback" && state.ProductVersion == manifest.ProductVersion {
		err = errors.New("rollback requires a different cached release")
		return append(phases, failed("Verify Windows lifecycle transition", err)), err
	}
	packageArtifacts, setupArtifact, err := windowsPackageArtifacts(manifest, packageManifest)
	if err != nil {
		return append(phases, failed("Select verified Windows package", err)), err
	}
	for _, artifact := range packageArtifacts {
		cachePath := a.executor.cachePath(artifact)
		if input.Plan.Operation == "rollback" && !cachedArtifactMatches(cachePath, artifact) {
			err = errors.New("the requested rollback package is not complete in the verified local release cache")
			return append(phases, failed("Verify rollback availability", err)), err
		}
		if !cachedArtifactMatches(cachePath, artifact) {
			if _, err = a.executor.downloadArtifact(ctx, artifact, ""); err != nil {
				return append(phases, failed("Download and verify Windows package", err)), err
			}
		}
	}
	staging, setupPath, err := a.stageWindowsPackage(packageArtifacts, setupArtifact)
	if err != nil {
		return append(phases, failed("Stage verified Windows package", err)), err
	}
	defer os.RemoveAll(staging)
	phases = append(phases, pass("Stage verified Windows package", "Scout staged the exact setup, RELEASES metadata, and package payloads from the verified cache using their manifest names."))
	if unsignedPreview {
		phases = append(phases, pass("Verify explicit unsigned Preview setup", "The exact cached setup uses the required visible unsigned Preview filename and is independently pinned by the official product manifest; Authenticode was not claimed."))
	} else {
		if err = a.system().VerifyAuthenticode(setupPath, packageManifest.Signature); err != nil {
			return append(phases, failed("Verify Windows setup signature", err)), err
		}
		phases = append(phases, pass("Verify Windows setup signature", "The exact cached setup has the manifest-declared valid Authenticode signer."))
	}
	commandContext, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	if _, err = a.system().Run(commandContext, setupPath, []string{"--silent"}); err != nil {
		return append(phases, failed("Apply Windows client "+input.Plan.Operation, err)), err
	}
	phases = append(phases, pass("Apply Windows client "+input.Plan.Operation, "The verified current-user setup completed without shell interpolation."))
	paths, err := a.system().Paths(manifest.ProductVersion)
	if err != nil {
		return append(phases, failed("Locate installed Windows client", err)), err
	}
	if !unsignedPreview {
		if err = a.system().VerifyAuthenticode(paths.Application, packageManifest.Signature); err != nil {
			return append(phases, failed("Verify installed Windows application signature", err)), err
		}
	}
	checkContext, cancelCheck := context.WithTimeout(ctx, 90*time.Second)
	defer cancelCheck()
	smoke, smokeErr := a.system().HealthSmoke(checkContext, paths.Application)
	if smokeErr != nil || validateWindowsSmoke(smoke) != nil {
		err = errors.Join(smokeErr, validateWindowsSmoke(smoke))
		return append(phases, failed("Verify installed Windows client health", err)), err
	}
	healthDetail := "The installed client retained the expected signer and passed loopback, authorization, renderer sandbox, bridge, exact product identity, and product-shell smoke checks."
	if unsignedPreview {
		healthDetail = "The explicitly unsigned Preview client passed loopback, authorization, renderer sandbox, bridge, exact product identity, and product-shell smoke checks."
	}
	phases = append(phases, pass("Verify installed Windows client health", healthDetail))
	state = windowsClientState{SchemaVersion: 1, Installed: true, ProductVersion: manifest.ProductVersion, PackageManifestSha256: packageArtifact.Sha256, SetupSha256: setupArtifact.Sha256}
	if err = stateStore.save(state); err != nil {
		return append(phases, failed("Record Windows lifecycle state", err)), err
	}
	return append(phases, pass("Record Windows lifecycle state", "Scout recorded only version and verification hashes; no credentials or local paths were stored.")), nil
}

func (a *windowsClientAdapter) uninstall(ctx context.Context, input request, manifest releaseManifest, packageManifest windowsPackageManifest, stateStore *windowsClientStateStore, state windowsClientState, phases []phase) ([]phase, error) {
	if !input.Plan.KeepDataOnUninstall {
		err := errors.New("permanent data deletion was planned but not executed")
		return append(phases, failed("Protect Windows client data", err)), err
	}
	if !state.Installed {
		err := errors.New("Scout does not have an installed Windows client lifecycle record")
		return append(phases, failed("Verify installed Windows client state", err)), err
	}
	paths, err := a.system().Paths(state.ProductVersion)
	if err != nil {
		return append(phases, failed("Locate Windows uninstaller", err)), err
	}
	unsignedPreview, trustErr := validateWindowsPackageTrust(manifest, packageManifest)
	if trustErr != nil {
		return append(phases, failed("Verify Windows package trust", trustErr)), trustErr
	}
	if !unsignedPreview {
		if err = a.system().VerifyAuthenticode(paths.Updater, packageManifest.Signature); err != nil {
			return append(phases, failed("Verify Windows uninstaller signature", err)), err
		}
	}
	commandContext, cancel := context.WithTimeout(ctx, 3*time.Minute)
	defer cancel()
	if _, err = a.system().Run(commandContext, paths.Updater, []string{"--uninstall", "-s"}); err != nil {
		return append(phases, failed("Uninstall Windows application", err)), err
	}
	state.Installed = false
	state.DataRetained = true
	if err = stateStore.save(state); err != nil {
		return append(phases, failed("Record keep-data uninstall", err)), err
	}
	uninstallDetail := "The signed current-user uninstaller removed application binaries using an argument array."
	if unsignedPreview {
		uninstallDetail = "The explicitly unsigned Preview current-user uninstaller removed application binaries using an argument array after exact installed-state verification."
	}
	return append(phases,
		pass("Uninstall Windows application", uninstallDetail),
		pass("Retain Windows client data", "Standalone database, original media, backups, logs, and protected credentials were retained for reinstall or recovery."),
	), nil
}

func validateRuntimeArchivePath(value, operation string) (string, error) {
	if value == "" || !filepath.IsAbs(value) || strings.ToLower(filepath.Ext(value)) != ".albackup" {
		return "", errors.New("an absolute .albackup runtime location is required")
	}
	clean := filepath.Clean(value)
	if operation == "restore" {
		info, err := os.Lstat(clean)
		if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			return "", errors.New("the restore archive is missing or is not a safe regular file")
		}
		resolved, err := filepath.EvalSymlinks(clean)
		resolvedInfo, statErr := os.Stat(resolved)
		if err != nil || statErr != nil || !os.SameFile(info, resolvedInfo) {
			return "", errors.New("the restore archive uses an unsafe redirected path")
		}
		return resolved, nil
	}
	if operation != "backup" {
		return "", errors.New("the runtime archive operation is unsupported")
	}
	if _, err := os.Lstat(clean); err == nil {
		return "", errors.New("the backup archive already exists")
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", errors.New("the backup archive location is unavailable")
	}
	parent, err := filepath.EvalSymlinks(filepath.Dir(clean))
	if err != nil {
		return "", errors.New("the backup destination folder is unavailable")
	}
	info, err := os.Lstat(parent)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return "", errors.New("the backup destination folder is unsafe")
	}
	return filepath.Join(parent, filepath.Base(clean)), nil
}

func (a *windowsClientAdapter) runHeadlessLifecycle(ctx context.Context, input request, manifest releaseManifest, packageManifest windowsPackageManifest, state windowsClientState, phases []phase) ([]phase, error) {
	archivePath, err := validateRuntimeArchivePath(input.Secrets["windowsArchivePath"], input.Plan.Operation)
	if err != nil {
		return append(phases, failed("Validate runtime backup location", err)), err
	}
	paths, err := a.system().Paths(state.ProductVersion)
	if err != nil {
		err = errors.New("the installed Windows application could not be located safely")
		return append(phases, failed("Locate installed Windows application", err)), err
	}
	unsignedPreview, trustErr := validateWindowsPackageTrust(manifest, packageManifest)
	if trustErr != nil {
		return append(phases, failed("Verify Windows package trust", trustErr)), trustErr
	}
	if !unsignedPreview {
		if err = a.system().VerifyAuthenticode(paths.Application, packageManifest.Signature); err != nil {
			return append(phases, failed("Verify installed Windows application signature", err)), err
		}
	}
	directory, err := os.MkdirTemp("", "apiarylens-windows-lifecycle-")
	if err != nil {
		err = errors.New("Scout could not create protected lifecycle staging")
		return append(phases, failed("Prepare protected lifecycle request", err)), err
	}
	defer os.RemoveAll(directory)
	if err = os.Chmod(directory, 0o700); err != nil {
		err = errors.New("Scout could not protect lifecycle staging")
		return append(phases, failed("Prepare protected lifecycle request", err)), err
	}
	requestPath := filepath.Join(directory, "request.json")
	evidencePath := filepath.Join(directory, "evidence.json")
	requestDocument := windowsHeadlessRequest{
		SchemaVersion: 1,
		Operation:     input.Plan.Operation,
		ArchivePath:   archivePath,
		Expected: windowsHeadlessIdentity{
			ProductVersion:    manifest.ProductVersion,
			DatabaseMigration: manifest.Contracts.DatabaseMigration,
		},
	}
	rawRequest, err := json.Marshal(requestDocument)
	if err != nil {
		err = errors.New("Scout could not encode the lifecycle request")
		return append(phases, failed("Prepare protected lifecycle request", err)), err
	}
	if err = os.WriteFile(requestPath, append(rawRequest, '\n'), 0o600); err != nil {
		err = errors.New("Scout could not write protected lifecycle staging")
		return append(phases, failed("Prepare protected lifecycle request", err)), err
	}
	operationContext, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()
	_, runErr := a.system().Run(operationContext, paths.Application, []string{
		"--desktop-lifecycle-request=" + requestPath,
		"--desktop-lifecycle-evidence=" + evidencePath,
	})
	evidence, evidenceErr := readWindowsHeadlessEvidence(evidencePath, requestDocument, archivePath)
	if evidenceErr != nil {
		err = errors.New("the installed Windows client did not return valid lifecycle evidence")
		return append(phases, failed("Verify Windows "+input.Plan.Operation+" evidence", err)), err
	}
	if runErr != nil && evidence.Status == "passed" {
		err = errors.New("the installed Windows client returned inconsistent lifecycle status")
		return append(phases, failed("Verify Windows "+input.Plan.Operation+" evidence", err)), err
	}
	if evidence.Status != "passed" {
		err = fmt.Errorf("the installed Windows client reported %s failure", input.Plan.Operation)
		return append(phases, failed("Apply Windows "+input.Plan.Operation, err)), err
	}
	detail := fmt.Sprintf("The installed client verified %d database and media files using the exact %s/migration %s compatibility lock.", *evidence.Files, manifest.ProductVersion, manifest.Contracts.DatabaseMigration)
	return append(phases,
		pass("Apply Windows "+input.Plan.Operation, "The installed client completed the headless lifecycle operation without shell interpolation."),
		pass("Verify Windows "+input.Plan.Operation+" evidence", detail),
	), nil
}

func readWindowsHeadlessEvidence(path string, request windowsHeadlessRequest, archivePath string) (windowsHeadlessEvidence, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() <= 0 || info.Size() > 64<<10 {
		return windowsHeadlessEvidence{}, errors.New("lifecycle evidence file is missing or unsafe")
	}
	raw, err := os.ReadFile(path)
	if err != nil || bytes.Contains(raw, []byte(archivePath)) {
		return windowsHeadlessEvidence{}, errors.New("lifecycle evidence contains disallowed data")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var evidence windowsHeadlessEvidence
	if err = decoder.Decode(&evidence); err != nil {
		return windowsHeadlessEvidence{}, errors.New("lifecycle evidence schema is invalid")
	}
	if err = decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return windowsHeadlessEvidence{}, errors.New("lifecycle evidence contains trailing data")
	}
	if evidence.SchemaVersion != 1 || evidence.Operation != request.Operation || evidence.ProductVersion != request.Expected.ProductVersion || evidence.DatabaseMigration != request.Expected.DatabaseMigration || (evidence.Status != "passed" && evidence.Status != "failed") {
		return windowsHeadlessEvidence{}, errors.New("lifecycle evidence identity does not match the request")
	}
	if evidence.SourceCreatedAt != "" {
		if _, err = time.Parse(time.RFC3339Nano, evidence.SourceCreatedAt); err != nil {
			return windowsHeadlessEvidence{}, errors.New("lifecycle evidence timestamp is invalid")
		}
	}
	if evidence.Status == "passed" {
		if evidence.ErrorCode != "" || evidence.Files == nil || *evidence.Files < 1 {
			return windowsHeadlessEvidence{}, errors.New("successful lifecycle evidence is incomplete")
		}
		if request.Operation == "restore" && (evidence.RecoveryBackupVerified == nil || !*evidence.RecoveryBackupVerified || evidence.RollbackPerformed == nil) {
			return windowsHeadlessEvidence{}, errors.New("restore evidence does not prove recovery protection")
		}
		return evidence, nil
	}
	allowedErrors := map[string]bool{"invalid_request": true, "backup_failed": request.Operation == "backup", "restore_failed": request.Operation == "restore", "incompatible_backup": request.Operation == "restore"}
	if !allowedErrors[evidence.ErrorCode] {
		return windowsHeadlessEvidence{}, errors.New("failed lifecycle evidence has an unsupported error code")
	}
	return evidence, nil
}

func windowsPackageManifestArtifact(version, architecture string, manifest releaseManifest) (manifestArtifact, error) {
	if manifest.ProductVersion != "" && manifest.ProductVersion != version {
		return manifestArtifact{}, errors.New("Windows package version does not match the product release")
	}
	for _, artifact := range manifest.Artifacts {
		if artifact.Kind == "windows-package-manifest" && artifact.Target == "windows-"+architecture && artifact.Name == "windows-package.json" {
			return artifact, nil
		}
	}
	return manifestArtifact{}, errors.New("the product release does not contain an x64 Windows package manifest")
}

func readWindowsPackageManifest(path string, release releaseManifest, outer manifestArtifact) (windowsPackageManifest, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return windowsPackageManifest{}, err
	}
	var manifest windowsPackageManifest
	if err = json.Unmarshal(raw, &manifest); err != nil {
		return windowsPackageManifest{}, errors.New("the Windows package manifest is not valid JSON")
	}
	if manifest.SchemaVersion != 1 || manifest.Product != "ApiaryLens for Windows" || manifest.ProductVersion != release.ProductVersion || manifest.Architecture != "x64" || manifest.PackageKind != "squirrel-current-user" || manifest.SourceCommit != release.SourceCommit {
		return windowsPackageManifest{}, errors.New("the Windows package identity does not match the product release")
	}
	if _, err = validateWindowsPackageTrust(release, manifest); err != nil {
		return windowsPackageManifest{}, err
	}
	if !cachedArtifactMatches(path, outer) {
		return windowsPackageManifest{}, errors.New("the cached Windows package manifest no longer matches its release identity")
	}
	return manifest, nil
}

func validateWindowsPackageTrust(release releaseManifest, manifest windowsPackageManifest) (bool, error) {
	if manifest.Signed {
		if !safePublisher(manifest.Signature.Publisher) || !validThumbprint(manifest.Signature.Thumbprint) {
			return false, errors.New("the signed Windows package does not declare a valid production signer")
		}
		return false, nil
	}
	if release.Channel != "preview" {
		return false, errors.New("unsigned Windows packages are permitted only for an explicit product Preview")
	}
	if manifest.Signature.Publisher != "" || manifest.Signature.Thumbprint != "" {
		return false, errors.New("the unsigned Preview package declares an unexpected signer identity")
	}
	return true, nil
}

func windowsPackageArtifacts(release releaseManifest, windows windowsPackageManifest) ([]manifestArtifact, manifestArtifact, error) {
	if len(windows.Artifacts) < 3 {
		return nil, manifestArtifact{}, errors.New("the Windows package must contain setup, RELEASES metadata, and a package payload")
	}
	resolved := make([]manifestArtifact, 0, len(windows.Artifacts))
	seen := map[string]bool{}
	var setup manifestArtifact
	hasReleases := false
	hasPackage := false
	unsignedPreview, err := validateWindowsPackageTrust(release, windows)
	if err != nil {
		return nil, manifestArtifact{}, err
	}
	expectedSetupName := "ApiaryLensSetup.exe"
	if unsignedPreview {
		expectedSetupName = "ApiaryLensSetup-UNSIGNED-PREVIEW.exe"
	}
	for _, packageArtifact := range windows.Artifacts {
		if packageArtifact.Name == "" || filepath.Base(packageArtifact.Name) != packageArtifact.Name || seen[strings.ToLower(packageArtifact.Name)] || !validSha256(packageArtifact.Sha256) || packageArtifact.Bytes <= 0 {
			return nil, manifestArtifact{}, errors.New("the Windows package contains an invalid or duplicate artifact identity")
		}
		seen[strings.ToLower(packageArtifact.Name)] = true
		found := false
		lowerName := strings.ToLower(packageArtifact.Name)
		if strings.HasPrefix(lowerName, "apiarylenssetup") && strings.HasSuffix(lowerName, ".exe") && packageArtifact.Name != expectedSetupName {
			return nil, manifestArtifact{}, errors.New("the Windows package setup filename is ambiguous or does not match its signing policy")
		}
		for _, artifact := range release.Artifacts {
			if artifact.Name == packageArtifact.Name && artifact.Kind == "windows-package-artifact" && artifact.Target == windowsTarget && strings.EqualFold(artifact.Sha256, packageArtifact.Sha256) && artifact.Bytes == packageArtifact.Bytes {
				resolved = append(resolved, artifact)
				found = true
				if artifact.Name == expectedSetupName {
					setup = artifact
				}
				if artifact.Name == "RELEASES" {
					hasReleases = true
				}
				if strings.HasSuffix(strings.ToLower(artifact.Name), ".nupkg") {
					hasPackage = true
				}
				break
			}
		}
		if !found {
			return nil, manifestArtifact{}, fmt.Errorf("Windows package artifact %q is not independently pinned by the product release manifest", packageArtifact.Name)
		}
	}
	if setup.Name == "" || !hasReleases || !hasPackage {
		return nil, manifestArtifact{}, errors.New("the Windows package is missing setup, RELEASES metadata, or its package payload")
	}
	return resolved, setup, nil
}

func (a *windowsClientAdapter) stageWindowsPackage(artifacts []manifestArtifact, setup manifestArtifact) (string, string, error) {
	directory, err := os.MkdirTemp("", "apiarylens-windows-package-")
	if err != nil {
		return "", "", err
	}
	fail := func(err error) (string, string, error) {
		_ = os.RemoveAll(directory)
		return "", "", err
	}
	for _, artifact := range artifacts {
		source := a.executor.cachePath(artifact)
		if !cachedArtifactMatches(source, artifact) {
			return fail(fmt.Errorf("cached Windows artifact %q changed before staging", artifact.Name))
		}
		raw, readErr := os.ReadFile(source)
		if readErr != nil {
			return fail(readErr)
		}
		if writeErr := os.WriteFile(filepath.Join(directory, artifact.Name), raw, 0o600); writeErr != nil {
			return fail(writeErr)
		}
	}
	return directory, filepath.Join(directory, setup.Name), nil
}

func safePublisher(value string) bool {
	return len(value) >= 3 && len(value) <= 120 && !strings.ContainsAny(value, "\r\n\x00")
}

func validThumbprint(value string) bool {
	if len(value) != 40 && len(value) != 64 {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func validateWindowsSmoke(result windowsSmokeEvidence) error {
	if !result.LoopbackOnly || !result.UnauthorizedRequestRejected || !result.AuthenticatedHealthPassed || !result.ProductShellServed || !result.SandboxedRenderer || result.ControlTokenExposed || strings.Join(result.BridgeKeys, ",") != "runtimeStatus,bootstrapOwner,createStandaloneBackup,restoreStandaloneBackup" {
		return errors.New("the installed client failed one or more security or health checks")
	}
	return nil
}

var squirrelPrerelease = regexp.MustCompile(`-(preview|rc)\.(\d+)$`)

func squirrelVersion(productVersion string) string {
	return squirrelPrerelease.ReplaceAllString(productVersion, `-$1$2`)
}

type windowsClientStateStore struct{ path string }

func (a *windowsClientAdapter) newStateStore() (*windowsClientStateStore, error) {
	directory := a.executor.windowsStateDirectory
	if directory == "" {
		root, err := os.UserConfigDir()
		if err != nil || root == "" {
			return nil, errors.New("the Scout Bee configuration folder is unavailable")
		}
		directory = filepath.Join(root, "ApiaryLens", "ScoutBee", "windows-client")
	}
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return nil, err
	}
	return &windowsClientStateStore{path: filepath.Join(directory, "state.json")}, nil
}

func (s *windowsClientStateStore) load() (windowsClientState, error) {
	raw, err := os.ReadFile(s.path)
	if errors.Is(err, os.ErrNotExist) {
		raw, err = os.ReadFile(s.path + ".bak")
	}
	if err != nil {
		return windowsClientState{}, err
	}
	var state windowsClientState
	if json.Unmarshal(raw, &state) != nil || state.SchemaVersion != 1 || !validSha256(state.PackageManifestSha256) || !validSha256(state.SetupSha256) {
		return windowsClientState{}, errors.New("the Windows lifecycle state is invalid")
	}
	return state, nil
}

func (s *windowsClientStateStore) save(state windowsClientState) error {
	raw, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	temporary := s.path + ".tmp"
	if err = os.WriteFile(temporary, append(raw, '\n'), 0o600); err != nil {
		return err
	}
	backup := s.path + ".bak"
	_ = os.Remove(backup)
	if _, statErr := os.Stat(s.path); statErr == nil {
		if err = os.Rename(s.path, backup); err != nil {
			_ = os.Remove(temporary)
			return err
		}
	} else if !errors.Is(statErr, os.ErrNotExist) {
		_ = os.Remove(temporary)
		return statErr
	}
	if err = os.Rename(temporary, s.path); err != nil {
		_ = os.Rename(backup, s.path)
		return err
	}
	_ = os.Remove(backup)
	return nil
}

func (e *executor) cachePath(artifact manifestArtifact) string {
	return filepath.Join(e.cacheDirectory, strings.ToLower(artifact.Sha256)+"-"+filepath.Base(artifact.Name))
}
