package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

type recordedWindowsRun struct {
	executable string
	args       []string
}

type fakeWindowsLifecycle struct {
	paths            windowsLifecyclePaths
	runs             []recordedWindowsRun
	verified         []string
	signatureErr     error
	healthCalls      int
	headlessEvidence *windowsHeadlessEvidence
	headlessRaw      []byte
	headlessRunErr   error
	headlessRequests []windowsHeadlessRequest
}

func (f *fakeWindowsLifecycle) Supported() bool                             { return true }
func (f *fakeWindowsLifecycle) Paths(string) (windowsLifecyclePaths, error) { return f.paths, nil }
func (f *fakeWindowsLifecycle) VerifyAuthenticode(path string, _ windowsPackageSignature) error {
	f.verified = append(f.verified, path)
	return f.signatureErr
}
func (f *fakeWindowsLifecycle) Run(_ context.Context, executable string, args []string) (string, error) {
	f.runs = append(f.runs, recordedWindowsRun{executable: executable, args: append([]string(nil), args...)})
	if len(args) == 2 && strings.HasPrefix(args[0], "--desktop-lifecycle-request=") && strings.HasPrefix(args[1], "--desktop-lifecycle-evidence=") {
		requestPath := strings.TrimPrefix(args[0], "--desktop-lifecycle-request=")
		evidencePath := strings.TrimPrefix(args[1], "--desktop-lifecycle-evidence=")
		rawRequest, err := os.ReadFile(requestPath)
		if err != nil {
			return "", err
		}
		var request windowsHeadlessRequest
		if err = json.Unmarshal(rawRequest, &request); err != nil {
			return "", err
		}
		f.headlessRequests = append(f.headlessRequests, request)
		rawEvidence := f.headlessRaw
		if rawEvidence == nil {
			evidence := f.headlessEvidence
			if evidence == nil {
				files := 1
				evidence = &windowsHeadlessEvidence{SchemaVersion: 1, Operation: request.Operation, Status: "passed", ProductVersion: request.Expected.ProductVersion, DatabaseMigration: request.Expected.DatabaseMigration, Files: &files}
			}
			rawEvidence, _ = json.Marshal(evidence)
		}
		if err = os.WriteFile(evidencePath, rawEvidence, 0o600); err != nil {
			return "", err
		}
		return "", f.headlessRunErr
	}
	return "", nil
}
func (f *fakeWindowsLifecycle) HealthSmoke(_ context.Context, executable string) (windowsSmokeEvidence, error) {
	f.healthCalls++
	if executable != f.paths.Application {
		return windowsSmokeEvidence{}, errors.New("wrong health executable")
	}
	return windowsSmokeEvidence{
		LoopbackOnly: true, UnauthorizedRequestRejected: true, AuthenticatedHealthPassed: true,
		ProductShellServed: true, SandboxedRenderer: true,
		BridgeKeys: []string{"runtimeStatus", "bootstrapOwner", "createStandaloneBackup", "restoreStandaloneBackup"},
	}, nil
}

func testDigest(value []byte) string {
	digest := sha256.Sum256(value)
	return hex.EncodeToString(digest[:])
}

func windowsAdapterFixture(t *testing.T, cacheSetup bool) (*windowsClientAdapter, releaseManifest, request, *fakeWindowsLifecycle) {
	t.Helper()
	cache := t.TempDir()
	state := t.TempDir()
	install := filepath.Join(t.TempDir(), "ApiaryLens")
	system := &fakeWindowsLifecycle{paths: windowsLifecyclePaths{
		InstallRoot: install,
		Updater:     filepath.Join(install, "Update.exe"), Application: filepath.Join(install, "current", "ApiaryLens.exe"),
	}}
	setupBytes := []byte("verified-windows-setup")
	setup := manifestArtifact{
		Name: "ApiaryLensSetup.exe", Kind: "windows-package-artifact", Target: windowsTarget,
		URL: "https://apiarylens.org/releases/test/ApiaryLensSetup.exe", Sha256: testDigest(setupBytes), Bytes: int64(len(setupBytes)),
	}
	releasesBytes := []byte("release-metadata")
	releases := manifestArtifact{
		Name: "RELEASES", Kind: "windows-package-artifact", Target: windowsTarget,
		URL: "https://apiarylens.org/releases/test/RELEASES", Sha256: testDigest(releasesBytes), Bytes: int64(len(releasesBytes)),
	}
	packageBytesPayload := []byte("squirrel-package")
	packagePayload := manifestArtifact{
		Name: "apiarylens-0.1.0-preview.1-full.nupkg", Kind: "windows-package-artifact", Target: windowsTarget,
		URL: "https://apiarylens.org/releases/test/apiarylens.nupkg", Sha256: testDigest(packageBytesPayload), Bytes: int64(len(packageBytesPayload)),
	}
	packageDocument := windowsPackageManifest{
		SchemaVersion: 1, Product: "ApiaryLens for Windows", ProductVersion: "0.1.0-preview.1",
		Architecture: "x64", PackageKind: "squirrel-current-user", SourceCommit: strings.Repeat("a", 40), Signed: true,
		Signature: windowsPackageSignature{Publisher: "ApiaryLens", Thumbprint: strings.Repeat("A", 40)},
		Artifacts: []windowsPackageArtifact{
			{Name: setup.Name, Sha256: setup.Sha256, Bytes: setup.Bytes},
			{Name: releases.Name, Sha256: releases.Sha256, Bytes: releases.Bytes},
			{Name: packagePayload.Name, Sha256: packagePayload.Sha256, Bytes: packagePayload.Bytes},
		},
	}
	packageBytes, err := json.Marshal(packageDocument)
	if err != nil {
		t.Fatal(err)
	}
	packageArtifact := manifestArtifact{
		Name: "windows-package.json", Kind: "windows-package-manifest", Target: windowsTarget,
		URL: "https://apiarylens.org/releases/test/windows-package.json", Sha256: testDigest(packageBytes), Bytes: int64(len(packageBytes)),
	}
	manifest := releaseManifest{
		Product: "ApiaryLens", ProductVersion: packageDocument.ProductVersion, Channel: "preview", SourceCommit: packageDocument.SourceCommit,
		Contracts: manifestContracts{DeploymentPlan: 1, DatabaseMigration: "0004"}, Artifacts: []manifestArtifact{packageArtifact, setup, releases, packagePayload},
	}
	executor := &executor{cacheDirectory: cache, windowsStateDirectory: state, windows: system}
	if err = os.WriteFile(executor.cachePath(packageArtifact), packageBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	if cacheSetup {
		if err = os.WriteFile(executor.cachePath(setup), setupBytes, 0o600); err != nil {
			t.Fatal(err)
		}
		if err = os.WriteFile(executor.cachePath(releases), releasesBytes, 0o600); err != nil {
			t.Fatal(err)
		}
		if err = os.WriteFile(executor.cachePath(packagePayload), packageBytesPayload, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	input := request{Mode: "apply", Plan: plan{
		SchemaVersion: 1, PlanID: "11111111-1111-4111-8111-111111111111", CreatedAt: time.Now().UTC().Format(time.RFC3339),
		Release:   release{Version: manifest.ProductVersion, Channel: "preview", ManifestURL: "https://apiarylens.org/releases/test/manifest.json", ManifestSha256: strings.Repeat("b", 64)},
		Operation: "install", KeepDataOnUninstall: true, Target: "windows-client", WindowsClient: &windowsClient{Architecture: "x64"},
	}}
	return &windowsClientAdapter{executor: executor}, manifest, input, system
}

func unsignedWindowsAdapterFixture(t *testing.T) (*windowsClientAdapter, releaseManifest, request, *fakeWindowsLifecycle, windowsPackageManifest) {
	t.Helper()
	adapter, manifest, input, system := windowsAdapterFixture(t, true)
	outer := manifest.Artifacts[0]
	path := adapter.executor.cachePath(outer)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var packageManifest windowsPackageManifest
	if err = json.Unmarshal(raw, &packageManifest); err != nil {
		t.Fatal(err)
	}
	packageManifest.Signed = false
	packageManifest.Signature = windowsPackageSignature{}
	packageManifest.Artifacts[0].Name = "ApiaryLensSetup-UNSIGNED-PREVIEW.exe"

	setupBytes, err := os.ReadFile(adapter.executor.cachePath(manifest.Artifacts[1]))
	if err != nil {
		t.Fatal(err)
	}
	manifest.Artifacts[1].Name = packageManifest.Artifacts[0].Name
	manifest.Artifacts[1].URL = "https://apiarylens.org/releases/test/ApiaryLensSetup-UNSIGNED-PREVIEW.exe"
	if err = os.WriteFile(adapter.executor.cachePath(manifest.Artifacts[1]), setupBytes, 0o600); err != nil {
		t.Fatal(err)
	}

	raw, err = json.Marshal(packageManifest)
	if err != nil {
		t.Fatal(err)
	}
	manifest.Artifacts[0].Sha256 = testDigest(raw)
	manifest.Artifacts[0].Bytes = int64(len(raw))
	if err = os.WriteFile(adapter.executor.cachePath(manifest.Artifacts[0]), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	return adapter, manifest, input, system, packageManifest
}

func TestWindowsClientInstallUsesVerifiedArgumentArraysAndSecretFreeState(t *testing.T) {
	adapter, manifest, input, system := windowsAdapterFixture(t, true)
	phases, err := adapter.apply(context.Background(), input, manifest)
	if err != nil {
		t.Fatalf("install failed: %v (%+v)", err, phases)
	}
	if len(system.runs) != 1 || !reflect.DeepEqual(system.runs[0].args, []string{"--silent"}) {
		t.Fatalf("unexpected lifecycle commands: %+v", system.runs)
	}
	state, err := adapter.newStateStore()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(state.path)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"password", "token", "secret", installPathFragment(system.paths.InstallRoot)} {
		if forbidden != "" && strings.Contains(strings.ToLower(string(raw)), strings.ToLower(forbidden)) {
			t.Fatalf("lifecycle state contains forbidden value %q: %s", forbidden, raw)
		}
	}
}

func TestWindowsClientInstallAcceptsExplicitUnsignedPreviewWithoutClaimingAuthenticode(t *testing.T) {
	adapter, manifest, input, system, _ := unsignedWindowsAdapterFixture(t)
	system.signatureErr = errors.New("Authenticode must not run for an explicit unsigned Preview")
	phases, err := adapter.apply(context.Background(), input, manifest)
	if err != nil {
		t.Fatalf("explicit unsigned Preview install failed: %v (%+v)", err, phases)
	}
	if len(system.verified) != 0 {
		t.Fatalf("unsigned Preview unexpectedly invoked Authenticode: %+v", system.verified)
	}
	if len(system.runs) != 1 || filepath.Base(system.runs[0].executable) != "ApiaryLensSetup-UNSIGNED-PREVIEW.exe" {
		t.Fatalf("unexpected unsigned Preview setup execution: %+v", system.runs)
	}
	if system.healthCalls != 1 {
		t.Fatalf("unsigned Preview skipped installed security/health smoke: %d", system.healthCalls)
	}
	foundPolicyPhase := false
	for _, current := range phases {
		foundPolicyPhase = foundPolicyPhase || current.Name == "Verify explicit unsigned Preview setup" && strings.Contains(current.Detail, "independently pinned") && strings.Contains(current.Detail, "Authenticode was not claimed")
	}
	if !foundPolicyPhase {
		t.Fatalf("unsigned Preview evidence phase is missing or inaccurate: %+v", phases)
	}
}

func TestWindowsClientSignedStableStillRequiresAuthenticode(t *testing.T) {
	adapter, manifest, input, system := windowsAdapterFixture(t, true)
	manifest.Channel = "stable"
	input.Plan.Release.Channel = "stable"
	if _, err := adapter.apply(context.Background(), input, manifest); err != nil {
		t.Fatalf("signed Stable install failed: %v", err)
	}
	if len(system.verified) != 2 {
		t.Fatalf("signed Stable must verify setup and installed application Authenticode: %+v", system.verified)
	}
}

func TestWindowsClientSignedStableFailsClosedOnAuthenticodeError(t *testing.T) {
	adapter, manifest, input, system := windowsAdapterFixture(t, true)
	manifest.Channel = "stable"
	input.Plan.Release.Channel = "stable"
	system.signatureErr = errors.New("unexpected signer")
	phases, err := adapter.apply(context.Background(), input, manifest)
	if err == nil || len(system.runs) != 0 || system.healthCalls != 0 {
		t.Fatalf("signed Stable Authenticode failure did not stop before execution: err=%v phases=%+v runs=%+v", err, phases, system.runs)
	}
}

func TestUnsignedPreviewSkipsAuthenticodeForManagedBackupAndUninstallOnly(t *testing.T) {
	adapter, manifest, input, system, _ := unsignedWindowsAdapterFixture(t)
	system.signatureErr = errors.New("Authenticode must not run for an explicit unsigned Preview")
	if _, err := adapter.apply(context.Background(), input, manifest); err != nil {
		t.Fatal(err)
	}
	system.runs = nil
	input.Plan.Operation = "backup"
	input.Secrets = map[string]string{"windowsArchivePath": filepath.Join(t.TempDir(), "family.albackup")}
	if _, err := adapter.apply(context.Background(), input, manifest); err != nil {
		t.Fatalf("unsigned Preview managed backup failed: %v", err)
	}
	input.Plan.Operation = "uninstall"
	input.Secrets = nil
	if _, err := adapter.apply(context.Background(), input, manifest); err != nil {
		t.Fatalf("unsigned Preview managed uninstall failed: %v", err)
	}
	if len(system.verified) != 0 {
		t.Fatalf("unsigned Preview lifecycle unexpectedly invoked Authenticode: %+v", system.verified)
	}
}

func installPathFragment(path string) string { return filepath.Base(filepath.Dir(path)) }

func TestWindowsClientKeepDataUninstallUsesSignedUpdater(t *testing.T) {
	adapter, manifest, input, system := windowsAdapterFixture(t, true)
	if _, err := adapter.apply(context.Background(), input, manifest); err != nil {
		t.Fatal(err)
	}
	system.runs = nil
	input.Plan.Operation = "uninstall"
	phases, err := adapter.apply(context.Background(), input, manifest)
	if err != nil {
		t.Fatalf("uninstall failed: %v (%+v)", err, phases)
	}
	if len(system.runs) != 1 || system.runs[0].executable != system.paths.Updater || !reflect.DeepEqual(system.runs[0].args, []string{"--uninstall", "-s"}) {
		t.Fatalf("unexpected uninstall command: %+v", system.runs)
	}
	store, _ := adapter.newStateStore()
	state, err := store.load()
	if err != nil || state.Installed || !state.DataRetained {
		t.Fatalf("unexpected retained state: %+v, %v", state, err)
	}
}

func TestWindowsClientPermanentDeleteIsPlanningOnly(t *testing.T) {
	adapter, _, input, _ := windowsAdapterFixture(t, true)
	input.Plan.Operation = "uninstall"
	input.Plan.KeepDataOnUninstall = false
	input.Mode = "dry-run"
	phases, err := adapter.preflight(context.Background(), input)
	if err != nil || len(phases) != 2 {
		t.Fatalf("dry-run deletion plan failed: %+v, %v", phases, err)
	}
	input.Mode = "apply"
	if _, err = adapter.preflight(context.Background(), input); err == nil || !strings.Contains(err.Error(), "separately confirmed") {
		t.Fatalf("apply should reject inferred permanent deletion: %v", err)
	}
}

func TestWindowsClientRejectsExportBeforeSetup(t *testing.T) {
	adapter, _, input, system := windowsAdapterFixture(t, true)
	input.Plan.Operation = "export"
	if _, err := adapter.preflight(context.Background(), input); err == nil || !strings.Contains(err.Error(), "not implemented") {
		t.Fatalf("export should fail closed: %v", err)
	}
	if len(system.runs) != 0 {
		t.Fatalf("unsupported operations executed Windows lifecycle commands: %+v", system.runs)
	}
}

func TestWindowsClientBackupUsesRuntimeOnlyArchiveAndAllowListedEvidence(t *testing.T) {
	adapter, manifest, input, system := windowsAdapterFixture(t, true)
	if _, err := adapter.apply(context.Background(), input, manifest); err != nil {
		t.Fatal(err)
	}
	system.runs = nil
	archivePath := filepath.Join(t.TempDir(), "family.albackup")
	expectedArchivePath, err := validateRuntimeArchivePath(archivePath, "backup")
	if err != nil {
		t.Fatal(err)
	}
	input.Plan.Operation = "backup"
	input.Secrets = map[string]string{"windowsArchivePath": archivePath}
	phases, err := adapter.apply(context.Background(), input, manifest)
	if err != nil {
		t.Fatalf("backup failed: %v; phases=%+v", err, phases)
	}
	if len(system.headlessRequests) != 1 || !sameWindowsPath(system.headlessRequests[0].ArchivePath, expectedArchivePath) {
		t.Fatalf("runtime archive was not handed to the installed client: %+v", system.headlessRequests)
	}
	for _, run := range system.runs {
		if strings.Contains(strings.Join(run.args, " "), archivePath) {
			t.Fatalf("archive path leaked into process arguments: %+v", run.args)
		}
	}
	encodedPhases, _ := json.Marshal(phases)
	if strings.Contains(string(encodedPhases), archivePath) {
		t.Fatalf("archive path leaked into phases: %s", encodedPhases)
	}
	store, _ := adapter.newStateStore()
	rawState, _ := os.ReadFile(store.path)
	if strings.Contains(string(rawState), archivePath) {
		t.Fatalf("archive path leaked into lifecycle state: %s", rawState)
	}
}

func TestWindowsClientRestoreFailureIsSanitizedAndDoesNotRunSetup(t *testing.T) {
	adapter, manifest, input, system := windowsAdapterFixture(t, true)
	if _, err := adapter.apply(context.Background(), input, manifest); err != nil {
		t.Fatal(err)
	}
	system.runs = nil
	archivePath := filepath.Join(t.TempDir(), "private-family-name.albackup")
	if err := os.WriteFile(archivePath, []byte("fixture"), 0o600); err != nil {
		t.Fatal(err)
	}
	rollback := true
	verified := true
	system.headlessEvidence = &windowsHeadlessEvidence{
		SchemaVersion: 1, Operation: "restore", Status: "failed",
		ProductVersion: manifest.ProductVersion, DatabaseMigration: manifest.Contracts.DatabaseMigration,
		RecoveryBackupVerified: &verified, RollbackPerformed: &rollback, RollbackVerified: &verified,
		ErrorCode: "restore_failed",
	}
	input.Plan.Operation = "restore"
	input.Secrets = map[string]string{"windowsArchivePath": archivePath}
	phases, err := adapter.apply(context.Background(), input, manifest)
	if err == nil || !strings.Contains(err.Error(), "reported restore failure") {
		t.Fatalf("restore failure was not propagated safely: %v", err)
	}
	encoded, _ := json.Marshal(phases)
	if strings.Contains(string(encoded), archivePath) || strings.Contains(string(encoded), "private-family-name") {
		t.Fatalf("restore path leaked into phases: %s", encoded)
	}
	for _, run := range system.runs {
		if reflect.DeepEqual(run.args, []string{"--silent"}) {
			t.Fatalf("restore unexpectedly ran Setup: %+v", system.runs)
		}
	}
}

func TestWindowsClientRejectsEvidenceWithPathField(t *testing.T) {
	adapter, manifest, input, system := windowsAdapterFixture(t, true)
	if _, err := adapter.apply(context.Background(), input, manifest); err != nil {
		t.Fatal(err)
	}
	archivePath := filepath.Join(t.TempDir(), "family.albackup")
	system.headlessRaw = []byte(`{"schemaVersion":1,"operation":"backup","status":"passed","productVersion":"0.1.0-preview.1","databaseMigration":"0004","files":1,"archivePath":"C:\\private\\family.albackup"}`)
	input.Plan.Operation = "backup"
	input.Secrets = map[string]string{"windowsArchivePath": archivePath}
	if _, err := adapter.apply(context.Background(), input, manifest); err == nil || !strings.Contains(err.Error(), "valid lifecycle evidence") {
		t.Fatalf("unknown evidence path field should fail closed: %v", err)
	}
}

func TestWindowsClientStateCanBeSafelyReplaced(t *testing.T) {
	store := &windowsClientStateStore{path: filepath.Join(t.TempDir(), "state.json")}
	first := windowsClientState{SchemaVersion: 1, Installed: true, ProductVersion: "0.1.0-preview.1", PackageManifestSha256: strings.Repeat("a", 64), SetupSha256: strings.Repeat("b", 64)}
	second := windowsClientState{SchemaVersion: 1, Installed: false, ProductVersion: "0.1.0-preview.1", PackageManifestSha256: strings.Repeat("a", 64), SetupSha256: strings.Repeat("b", 64), DataRetained: true}
	if err := store.save(first); err != nil {
		t.Fatal(err)
	}
	if err := store.save(second); err != nil {
		t.Fatal(err)
	}
	loaded, err := store.load()
	if err != nil || loaded.Installed || !loaded.DataRetained {
		t.Fatalf("state replacement failed: %+v, %v", loaded, err)
	}
}

func TestWindowsClientRollbackRequiresVerifiedCachedSetup(t *testing.T) {
	adapter, manifest, input, _ := windowsAdapterFixture(t, false)
	store, _ := adapter.newStateStore()
	_ = store.save(windowsClientState{SchemaVersion: 1, Installed: true, ProductVersion: "0.1.0-preview.2", PackageManifestSha256: strings.Repeat("c", 64), SetupSha256: strings.Repeat("d", 64)})
	input.Plan.Operation = "rollback"
	_, err := adapter.apply(context.Background(), input, manifest)
	if err == nil || !strings.Contains(err.Error(), "rollback package") {
		t.Fatalf("rollback should fail closed: %v", err)
	}
}

func TestWindowsPackageManifestRejectsUnsignedRCAndStable(t *testing.T) {
	adapter, manifest, _, _, _ := unsignedWindowsAdapterFixture(t)
	artifact := manifest.Artifacts[0]
	path := adapter.executor.cachePath(artifact)
	for _, channel := range []string{"release-candidate", "stable"} {
		changedRelease := manifest
		changedRelease.Channel = channel
		if _, err := readWindowsPackageManifest(path, changedRelease, artifact); err == nil || !strings.Contains(err.Error(), "only for an explicit product Preview") {
			t.Fatalf("unsigned %s package should fail closed: %v", channel, err)
		}
	}
}

func TestWindowsPackageManifestRejectsUnexpectedUnsignedSignerState(t *testing.T) {
	_, manifest, _, _, packageManifest := unsignedWindowsAdapterFixture(t)
	packageManifest.Signature = windowsPackageSignature{Publisher: "Unexpected Publisher", Thumbprint: strings.Repeat("A", 40)}
	if _, err := validateWindowsPackageTrust(manifest, packageManifest); err == nil || !strings.Contains(err.Error(), "unexpected signer") {
		t.Fatalf("unsigned package with signer state should fail closed: %v", err)
	}
}

func TestSignedWindowsPackageRejectsMissingSignerState(t *testing.T) {
	release := releaseManifest{Channel: "stable"}
	packageManifest := windowsPackageManifest{Signed: true}
	if _, err := validateWindowsPackageTrust(release, packageManifest); err == nil || !strings.Contains(err.Error(), "valid production signer") {
		t.Fatalf("signed package without signer metadata should fail closed: %v", err)
	}
}

func TestUnsignedWindowsPackageRejectsAmbiguousSetupName(t *testing.T) {
	_, manifest, _, _, packageManifest := unsignedWindowsAdapterFixture(t)
	packageManifest.Artifacts[0].Name = "ApiaryLensSetup.exe"
	if _, _, err := windowsPackageArtifacts(manifest, packageManifest); err == nil || !strings.Contains(err.Error(), "filename is ambiguous") {
		t.Fatalf("ambiguous unsigned setup name should fail closed: %v", err)
	}
}

func TestUnsignedWindowsPackageRequiresEveryArtifactPinnedByProductManifest(t *testing.T) {
	_, manifest, _, _, packageManifest := unsignedWindowsAdapterFixture(t)
	for _, missingName := range []string{"ApiaryLensSetup-UNSIGNED-PREVIEW.exe", "RELEASES", "apiarylens-0.1.0-preview.1-full.nupkg"} {
		changed := manifest
		changed.Artifacts = append([]manifestArtifact(nil), manifest.Artifacts...)
		for index, artifact := range changed.Artifacts {
			if artifact.Name == missingName {
				changed.Artifacts = append(changed.Artifacts[:index], changed.Artifacts[index+1:]...)
				break
			}
		}
		if _, _, err := windowsPackageArtifacts(changed, packageManifest); err == nil || !strings.Contains(err.Error(), "not independently pinned") {
			t.Fatalf("missing product pin for %s should fail closed: %v", missingName, err)
		}
	}
}

func TestResolveInstalledWindowsPathsSelectsExactDirectAppVersion(t *testing.T) {
	root := filepath.Join(t.TempDir(), "ApiaryLens")
	if err := os.MkdirAll(filepath.Join(root, "app-0.1.0-preview1"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "app-0.1.0-preview2"), 0o700); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{
		filepath.Join(root, "Update.exe"),
		filepath.Join(root, "app-0.1.0-preview1", "ApiaryLens.exe"),
		filepath.Join(root, "app-0.1.0-preview2", "ApiaryLens.exe"),
	} {
		if err := os.WriteFile(path, []byte("fixture"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	paths, err := resolveInstalledWindowsPaths(root, "0.1.0-preview.2")
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Base(filepath.Dir(paths.Application)) != "app-0.1.0-preview2" {
		t.Fatalf("resolved wrong application directory: %s", paths.Application)
	}
	if _, err = resolveInstalledWindowsPaths(root, "0.1.0-preview.3"); err == nil {
		t.Fatal("missing exact installed version should be rejected")
	}
}
