import { StrictMode, useEffect, useMemo, useState } from "react";
import { createRoot } from "react-dom/client";
import "./style.css";
import { availableTargets, type Target } from "./targets";

type Operation =
  | "install"
  | "update"
  | "repair"
  | "rollback"
  | "backup"
  | "restore"
  | "export"
  | "uninstall";
type ProductChannel = "preview" | "release-candidate" | "stable";
type SSHAuthMethod = "agent" | "private-key" | "password";
type Phase = {
  name: string;
  state: "waiting" | "running" | "passed" | "failed";
  detail?: string;
};

type ReleaseIdentity = {
  version: string;
  channel: ProductChannel;
  manifestUrl: string;
  manifestSha256: string;
};

type OperationSummary = {
  planId: string;
  operation: Operation;
  target: string;
  mode: string;
  status: string;
  startedAt: string;
  finishedAt?: string;
};

type WindowsConnectionProfile = {
  schemaVersion: 1;
  profileId: string;
  displayName: string;
  mode: "connected";
  clientKind: "windows";
  backendUrl: string;
  deploymentProfile: "cloudflare" | "compose";
  provisioningSource: "scout";
  createdAt: string;
  compatibility: {
    productVersion: string;
    apiContract: string;
    syncContract: number;
    databaseMigration: string;
  };
};

const cloudflareAllowances = [
  ["Workers", "100,000 dynamic requests each day"],
  [
    "D1 records",
    "5 million rows read and 100,000 rows written each day; 5 GB stored",
  ],
  [
    "R2 photos",
    "10 GB-month stored; 1 million Class A and 10 million Class B operations each month",
  ],
] as const;

const token = location.hash.slice(1);
const call = async <T,>(path: string, init?: RequestInit): Promise<T> => {
  const response = await fetch(path, {
    ...init,
    headers: {
      authorization: `Bearer ${token}`,
      "content-type": "application/json",
      ...init?.headers,
    },
  });
  const body = (await response.json().catch(() => ({}))) as {
    message?: string;
  };
  if (!response.ok)
    throw new Error(
      body.message ?? `Scout Bee could not continue (${response.status})`,
    );
  return body as T;
};

function App() {
  const [target, setTarget] = useState<Target>("cloudflare");
  const [operation, setOperation] = useState<Operation>("install");
  const [productChannel, setProductChannel] =
    useState<ProductChannel>("stable");
  const [cloudflareToken, setCloudflareToken] = useState("");
  const [bootstrapToken, setBootstrapToken] = useState("");
  const [sshAuthMethod, setSSHAuthMethod] = useState<SSHAuthMethod>("agent");
  const [sshPrivateKeyPath, setSSHPrivateKeyPath] = useState("");
  const [sshPrivateKeyPassphrase, setSSHPrivateKeyPassphrase] = useState("");
  const [sshPassword, setSSHPassword] = useState("");
  const [includeWebFrontend, setIncludeWebFrontend] = useState(true);
  const [keepData, setKeepData] = useState(true);
  const [costAcknowledged, setCostAcknowledged] = useState(false);
  const [restoreAcknowledged, setRestoreAcknowledged] = useState(false);
  const [step, setStep] = useState(1);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [phases, setPhases] = useState<Phase[]>([]);
  const [release, setRelease] = useState<ReleaseIdentity | null>(null);
  const [history, setHistory] = useState<OperationSummary[]>([]);
  const [connectionProfile, setConnectionProfile] =
    useState<WindowsConnectionProfile | null>(null);
  // Defaults to off: the Windows client target stays hidden unless the Scout
  // server explicitly reports SCOUT_BEE_ENABLE_WINDOWS_CLIENT (ADR 0023).
  const [windowsClientEnabled, setWindowsClientEnabled] = useState(false);
  const [form, setForm] = useState<Record<string, string>>({
    accountReference: "",
    workerName: "apiarylens-family",
    d1DatabaseName: "apiarylens-family",
    r2BucketName: "apiarylens-family-media",
    customDomain: "",
    backupDestination: "",
    backupFilePath: "",
    windowsArchivePath: "",
    host: "",
    user: "apiarylens",
    targetDirectory: "/opt/apiarylens",
    projectName: "apiarylens-family",
    publicUrl: "https://hives.example.com",
    sshHostKeySha256: "",
  });
  const plan = useMemo(
    () => ({
      schemaVersion: 1,
      planId: crypto.randomUUID(),
      createdAt: new Date().toISOString(),
      release:
        release ??
        ({
          version: "",
          channel: productChannel,
          manifestUrl: "",
          manifestSha256: "",
        } as const),
      operation,
      keepDataOnUninstall: keepData,
      target: target === "plan-only" ? "cloudflare" : target,
      ...(target === "compose-ssh"
        ? {
            compose: {
              host: form.host,
              port: 22,
              user: form.user,
              targetDirectory: form.targetDirectory,
              projectName: form.projectName,
              publicUrl: form.publicUrl,
              sshHostKeySha256: form.sshHostKeySha256,
              backupRetention: 14,
              includeWebFrontend,
            },
          }
        : target === "windows-client"
          ? { windowsClient: { architecture: "x64" } }
          : {
              cloudflare: {
                accountReference: form.accountReference,
                workerName: form.workerName,
                d1DatabaseName: form.d1DatabaseName,
                r2BucketName: form.r2BucketName,
                ...(form.customDomain
                  ? { customDomain: form.customDomain }
                  : {}),
                costProfile: "family-free-guarded",
                includeWebFrontend,
              },
            }),
    }),
    [
      target,
      form,
      operation,
      keepData,
      release,
      productChannel,
      includeWebFrontend,
    ],
  );
  useEffect(() => {
    setRelease(null);
    setError("");
    const advanced = productChannel === "stable" ? "" : "&advanced=true";
    void call<ReleaseIdentity>(
      `/api/v1/release?channel=${productChannel}${advanced}`,
    )
      .then(setRelease)
      .catch((caught) =>
        setError(
          productChannel === "stable"
            ? "No compatible Stable release is currently available. Preview and RC builds are available only through Advanced release channel opt-in."
            : caught instanceof Error
              ? caught.message
              : "The release identity is unavailable",
        ),
      );
  }, [productChannel]);
  async function refreshHistory() {
    const result = await call<{ items: OperationSummary[] }>("/api/v1/history");
    setHistory(result.items);
  }
  useEffect(() => {
    void refreshHistory().catch(() => undefined);
  }, []);
  useEffect(() => {
    void call<{ windowsClientEnabled?: boolean }>("/api/v1/status")
      .then((status) =>
        setWindowsClientEnabled(status.windowsClientEnabled === true),
      )
      .catch(() => undefined);
  }, []);
  const update = (name: string, value: string) =>
    setForm((current) => ({ ...current, [name]: value }));

  async function run(mode: "dry-run" | "apply" | "resume") {
    setBusy(true);
    setError("");
    try {
      const result = await call<{
        phases: Phase[];
        connectionProfile?: WindowsConnectionProfile;
      }>("/api/v1/execute", {
        method: "POST",
        body: JSON.stringify({
          plan,
          mode,
          secrets: {
            ...(target === "cloudflare" && cloudflareToken
              ? { cloudflareApiToken: cloudflareToken }
              : {}),
            ...(operation === "install" && bootstrapToken
              ? { bootstrapToken }
              : {}),
            ...(target === "compose-ssh"
              ? {
                  sshAuthMethod,
                  ...(sshAuthMethod === "private-key"
                    ? {
                        sshPrivateKeyPath,
                        ...(sshPrivateKeyPassphrase
                          ? { sshPrivateKeyPassphrase }
                          : {}),
                      }
                    : {}),
                  ...(sshAuthMethod === "password" ? { sshPassword } : {}),
                }
              : {}),
            ...(target === "windows-client" &&
            (operation === "backup" || operation === "restore") &&
            form.windowsArchivePath
              ? { windowsArchivePath: form.windowsArchivePath }
              : {}),
            ...(target === "cloudflare" && form.backupDestination
              ? { backupDestination: form.backupDestination }
              : {}),
            ...(target === "cloudflare" && form.backupFilePath
              ? { backupFilePath: form.backupFilePath }
              : {}),
          },
        }),
      });
      setPhases(result.phases);
      setConnectionProfile(result.connectionProfile ?? null);
      await refreshHistory();
      setStep(4);
    } catch (caught) {
      setError(
        caught instanceof Error
          ? caught.message
          : "Scout Bee could not continue",
      );
    } finally {
      setBusy(false);
    }
  }
  async function cancel() {
    try {
      await call(`/api/v1/operations/${plan.planId}?action=cancel`, {
        method: "POST",
      });
    } catch (caught) {
      setError(
        caught instanceof Error
          ? caught.message
          : "Scout Bee could not cancel safely",
      );
    }
  }
  async function saveDiagnostics() {
    try {
      const diagnostics = await call<Record<string, unknown>>(
        `/api/v1/diagnostics/${plan.planId}`,
      );
      const blob = new Blob([JSON.stringify(diagnostics, null, 2)], {
        type: "application/json",
      });
      const a = document.createElement("a");
      a.href = URL.createObjectURL(blob);
      a.download = `apiarylens-scout-diagnostics-${plan.planId}.json`;
      a.click();
      URL.revokeObjectURL(a.href);
    } catch (caught) {
      setError(
        caught instanceof Error
          ? caught.message
          : "Scout Bee could not create diagnostics",
      );
    }
  }
  function exportPlan() {
    const blob = new Blob([JSON.stringify(plan, null, 2)], {
      type: "application/json",
    });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = "apiarylens-deployment.json";
    a.click();
    URL.revokeObjectURL(a.href);
  }
  function saveConnectionProfile() {
    if (!connectionProfile) return;
    const blob = new Blob([JSON.stringify(connectionProfile, null, 2)], {
      type: "application/json",
    });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = "apiarylens-windows-connection.json";
    a.click();
    URL.revokeObjectURL(a.href);
  }
  const lastVerifiedBackup = history.find(
    (item) =>
      item.operation === "backup" &&
      item.mode === "apply" &&
      item.status === "passed",
  );
  const lastRestore = history.find((item) => item.operation === "restore");

  return (
    <div className="shell">
      <aside>
        <div className="brand">
          <span>Scout Bee</span>
          <small>by ApiaryLens</small>
        </div>
        <ol>
          {[
            "Choose a home",
            "Deployment details",
            "Review the plan",
            "Preflight & apply",
          ].map((label, index) => (
            <li
              className={
                step === index + 1 ? "active" : step > index + 1 ? "done" : ""
              }
              key={label}
            >
              <b>{index + 1}</b>
              {label}
            </li>
          ))}
        </ol>
        <p className="privacy">
          Your credentials stay in memory and never enter the deployment plan or
          diagnostics.
        </p>
      </aside>
      <main>
        <header>
          <p className="eyebrow">Guided deployment</p>
          <h1>
            {step === 1
              ? "Where should your hive history live?"
              : step === 2
                ? "Tell Scout Bee where to work."
                : step === 3
                  ? "Review before anything changes."
                  : "Deployment progress"}
          </h1>
        </header>
        {error && (
          <div className="error" role="alert">
            {error}
          </div>
        )}
        {step === 1 && (
          <>
            <section className="targets">
              {availableTargets(windowsClientEnabled).map((definition) => (
                <button
                  className={target === definition.id ? "selected" : ""}
                  key={definition.id}
                  onClick={() => setTarget(definition.id)}
                >
                  <b>{definition.title}</b>
                  <span>{definition.subtitle}</span>
                  <p>{definition.description}</p>
                </button>
              ))}
            </section>
            <section
              className="recovery-status"
              aria-labelledby="recovery-status-heading"
            >
              <div>
                <p className="eyebrow">Recovery readiness</p>
                <h2 id="recovery-status-heading">Backup and restore history</h2>
                <p>
                  A browser or phone's offline working copy is not a server
                  backup. Scout backups include the deployment's records and
                  private media.
                </p>
              </div>
              <dl>
                <div>
                  <dt>Last verified backup</dt>
                  <dd>
                    {lastVerifiedBackup?.finishedAt
                      ? new Date(lastVerifiedBackup.finishedAt).toLocaleString()
                      : "No verified Scout backup recorded on this computer"}
                  </dd>
                </div>
                <div>
                  <dt>Last restore attempt</dt>
                  <dd>
                    {lastRestore
                      ? `${lastRestore.status} · ${new Date(lastRestore.finishedAt ?? lastRestore.startedAt).toLocaleString()}`
                      : "No restore recorded on this computer"}
                  </dd>
                </div>
              </dl>
            </section>
            {target === "cloudflare" && <CloudflareCostGuide />}
          </>
        )}
        {step === 2 && (
          <section className="form">
            <label>
              What should Scout Bee do?
              <select
                value={operation}
                onChange={(event) => {
                  setOperation(event.target.value as Operation);
                  setRestoreAcknowledged(false);
                }}
              >
                <option value="install">Install a new deployment</option>
                <option value="update">Update an existing deployment</option>
                <option value="repair">
                  Repair using the same verified release
                </option>
                <option value="rollback">
                  Roll back to a selected compatible release
                </option>
                <option value="backup">Create and verify a backup</option>
                <option value="restore">Restore a verified backup</option>
                <option value="export" disabled={target === "windows-client"}>
                  Export owned data
                </option>
                <option value="uninstall">Uninstall ApiaryLens</option>
              </select>
            </label>
            <div className="release-selection">
              <b>Product release channel</b>
              <span>Stable is always selected by default.</span>
              <details>
                <summary>Advanced release channel</summary>
                <label>
                  Channel
                  <select
                    value={productChannel}
                    onChange={(event) =>
                      setProductChannel(event.target.value as ProductChannel)
                    }
                  >
                    <option value="stable">Stable</option>
                    <option value="preview">
                      Preview (changing frequently)
                    </option>
                    <option value="release-candidate">Release candidate</option>
                  </select>
                </label>
                <small>
                  Preview and RC builds can change frequently and require this
                  explicit advanced selection on every Scout installation.
                </small>
              </details>
            </div>
            {target !== "windows-client" && (
              <div
                className="frontend-selection"
                role="group"
                aria-labelledby="frontend-selection-label"
              >
                <b id="frontend-selection-label">Deployment content</b>
                <label>
                  <input
                    type="checkbox"
                    checked={includeWebFrontend}
                    onChange={(event) =>
                      setIncludeWebFrontend(event.target.checked)
                    }
                  />
                  Include the ApiaryLens web application
                </label>
                <small>
                  Clear this for a backend-only deployment used by connected
                  Windows or mobile clients. API, authentication, sync, media,
                  health checks, HTTPS, backup, and recovery remain enabled.
                </small>
              </div>
            )}
            {target === "compose-ssh" ? (
              <>
                <Field
                  label="Server address"
                  name="host"
                  value={form.host}
                  update={update}
                />
                <Field
                  label="Linux user"
                  name="user"
                  value={form.user}
                  update={update}
                />
                <Field
                  label="Install folder"
                  name="targetDirectory"
                  value={form.targetDirectory}
                  update={update}
                />
                <Field
                  label="Public HTTPS address"
                  name="publicUrl"
                  value={form.publicUrl}
                  update={update}
                />
                <Field
                  label="Verified SSH host key"
                  name="sshHostKeySha256"
                  value={form.sshHostKeySha256}
                  update={update}
                />
                <div className="ssh-authentication">
                  <label>
                    SSH authentication
                    <select
                      value={sshAuthMethod}
                      onChange={(event) => {
                        setSSHAuthMethod(event.target.value as SSHAuthMethod);
                        setSSHPrivateKeyPath("");
                        setSSHPrivateKeyPassphrase("");
                        setSSHPassword("");
                      }}
                    >
                      <option value="agent">
                        OpenSSH agent or default identity
                      </option>
                      <option value="private-key">
                        Explicit private key file
                      </option>
                      <option value="password">
                        Password (Windows Scout only)
                      </option>
                    </select>
                  </label>
                  {sshAuthMethod === "private-key" && (
                    <>
                      <label className="runtime-secret">
                        Private key file
                        <input
                          type="text"
                          autoComplete="off"
                          value={sshPrivateKeyPath}
                          onChange={(event) =>
                            setSSHPrivateKeyPath(event.target.value)
                          }
                          placeholder="C:\\Users\\you\\.ssh\\id_ed25519"
                        />
                        <small>
                          The absolute path is used only for this operation. It
                          is never added to the plan, history, logs, or
                          diagnostics.
                        </small>
                      </label>
                      <label className="runtime-secret">
                        Private key passphrase (optional; Windows Scout only)
                        <input
                          type="password"
                          autoComplete="off"
                          value={sshPrivateKeyPassphrase}
                          onChange={(event) =>
                            setSSHPrivateKeyPassphrase(event.target.value)
                          }
                          placeholder="Leave empty for an unencrypted key"
                        />
                        <small>
                          On Windows, Scout provides this through a protected,
                          temporary OpenSSH askpass boundary and deletes it when
                          the operation ends.
                        </small>
                      </label>
                    </>
                  )}
                  {sshAuthMethod === "password" && (
                    <label className="runtime-secret">
                      SSH password
                      <input
                        type="password"
                        autoComplete="off"
                        value={sshPassword}
                        onChange={(event) => setSSHPassword(event.target.value)}
                        placeholder="Used only during this operation"
                      />
                      <small>
                        On Windows, Scout provides this through a protected,
                        temporary OpenSSH askpass boundary and deletes it when
                        the operation ends.
                      </small>
                    </label>
                  )}
                  {sshAuthMethod === "agent" && (
                    <small>
                      Scout uses the current OpenSSH agent and default identity
                      files without prompting or persisting a credential.
                    </small>
                  )}
                </div>
              </>
            ) : target === "windows-client" ? (
              <>
                <div className="target-note" role="note">
                  <b>Current-user Windows installation</b>
                  <p>
                    Scout verifies the exact product manifest, package
                    checksums, and Authenticode signer before lifecycle work.
                    Backup and restore use protected runtime-only
                    request/evidence files; the archive path is never added to
                    the plan, history, logs, or diagnostics. Advanced Windows
                    data export remains unavailable.
                  </p>
                </div>
                {(operation === "backup" || operation === "restore") && (
                  <Field
                    label={
                      operation === "backup"
                        ? "New Windows backup file (.albackup)"
                        : "Existing Windows backup file (.albackup)"
                    }
                    name="windowsArchivePath"
                    value={form.windowsArchivePath}
                    update={update}
                    placeholder="C:\\Users\\you\\Documents\\apiarylens-family.albackup"
                  />
                )}
              </>
            ) : (
              <>
                <Field
                  label="Cloudflare account ID"
                  name="accountReference"
                  value={form.accountReference}
                  update={update}
                />
                <Field
                  label="ApiaryLens deployment name"
                  name="workerName"
                  value={form.workerName}
                  update={update}
                />
                <Field
                  label="Records database name"
                  name="d1DatabaseName"
                  value={form.d1DatabaseName}
                  update={update}
                />
                <Field
                  label="Private photo storage name"
                  name="r2BucketName"
                  value={form.r2BucketName}
                  update={update}
                />
                <Field
                  label="Deployment HTTPS address"
                  name="customDomain"
                  value={form.customDomain}
                  update={update}
                  placeholder="https://hives.example.com"
                />
                {(operation === "backup" ||
                  operation === "export" ||
                  operation === "update" ||
                  operation === "repair" ||
                  operation === "rollback") && (
                  <Field
                    label={
                      operation === "update" ||
                      operation === "repair" ||
                      operation === "rollback"
                        ? "Local folder for the required pre-update backup (optional)"
                        : "Local folder for the archive (optional)"
                    }
                    name="backupDestination"
                    value={form.backupDestination}
                    update={update}
                    placeholder="Defaults to your Downloads folder"
                  />
                )}
                {operation === "restore" && (
                  <Field
                    label="Verified backup file to restore"
                    name="backupFilePath"
                    value={form.backupFilePath}
                    update={update}
                    placeholder="C:\\Backups\\apiarylens-backup.zip"
                  />
                )}
              </>
            )}
          </section>
        )}
        {step === 3 && (
          <section>
            <div className="review">
              <div>
                <b>Release</b>
                <span>
                  {release
                    ? `${release.version} · ${release.channel}`
                    : "Loading…"}
                </span>
              </div>
              <div>
                <b>Target</b>
                <span>
                  {target === "compose-ssh"
                    ? "Your Linux server"
                    : target === "windows-client"
                      ? "This Windows account"
                      : target === "plan-only"
                        ? "Export only"
                        : "Your Cloudflare account"}
                </span>
              </div>
              <div>
                <b>Operation</b>
                <span>{operation}</span>
              </div>
              {target !== "windows-client" && (
                <div>
                  <b>Deployment content</b>
                  <span>
                    {includeWebFrontend
                      ? "Backend and web application"
                      : "Backend only"}
                  </span>
                </div>
              )}
              {target === "compose-ssh" && (
                <div>
                  <b>SSH authentication</b>
                  <span>
                    {sshAuthMethod === "agent"
                      ? "OpenSSH agent/default identity"
                      : sshAuthMethod === "private-key"
                        ? "Runtime-only private key"
                        : "Runtime-only password"}
                  </span>
                </div>
              )}
              <div>
                <b>Safety</b>
                <span>
                  {target === "windows-client"
                    ? "Package identity, checksums, Authenticode signer, installed host security, and health are verified before completion."
                    : "HTTPS, authentication, backup readiness, and versions are verified before completion."}
                </span>
              </div>
            </div>
            {target === "cloudflare" && (
              <>
                <CloudflareCostGuide />
                <label className="cost-acknowledgement">
                  <input
                    type="checkbox"
                    checked={costAcknowledged}
                    onChange={(event) =>
                      setCostAcknowledged(event.target.checked)
                    }
                  />
                  I reviewed these dated allowances and understand that
                  Cloudflare can change pricing or limits.
                </label>
                <label className="runtime-secret">
                  Cloudflare API token
                  <input
                    type="password"
                    autoComplete="off"
                    value={cloudflareToken}
                    onChange={(event) => setCloudflareToken(event.target.value)}
                    placeholder="Used only while this application is open"
                  />
                  <small>
                    This value stays in memory and is never added to the plan or
                    diagnostics.
                  </small>
                </label>
              </>
            )}
            {operation === "install" &&
              target !== "plan-only" &&
              target !== "windows-client" && (
                <label className="runtime-secret">
                  One-time owner setup code
                  <input
                    type="password"
                    autoComplete="new-password"
                    minLength={16}
                    value={bootstrapToken}
                    onChange={(event) => setBootstrapToken(event.target.value)}
                    placeholder="At least 16 characters; save it until setup is complete"
                  />
                  <small>
                    You will enter this code once when creating the first family
                    owner. It stays in memory here and is never added to the
                    plan or diagnostics.
                  </small>
                </label>
              )}
            {operation === "uninstall" && (
              <label className="keep-data">
                <input
                  type="checkbox"
                  checked={keepData}
                  onChange={(event) => setKeepData(event.target.checked)}
                />
                Keep database and media volumes so the deployment can be
                recovered later
              </label>
            )}
            {operation === "restore" && (
              <div className="restore-warning" role="note">
                <strong>
                  Restore replaces current{" "}
                  {target === "windows-client" ? "Windows" : "server"} records
                  and media.
                </strong>
                <p>
                  Scout first creates a recovery backup, verifies the selected
                  archive and target compatibility, restores the{" "}
                  {target === "windows-client" ? "Windows data" : "server"},
                  revokes existing sign-in sessions, and requires a passing
                  health check.
                </p>
                <label>
                  <input
                    type="checkbox"
                    checked={restoreAcknowledged}
                    onChange={(event) =>
                      setRestoreAcknowledged(event.target.checked)
                    }
                  />
                  I understand the current server data will be replaced and
                  users must sign in again.
                </label>
              </div>
            )}
            <details>
              <summary>View the operator plan</summary>
              <pre>{JSON.stringify(plan, null, 2)}</pre>
            </details>
          </section>
        )}
        {step === 4 && (
          <section className="progress">
            {phases.map((phase) => (
              <article className={phase.state} key={phase.name}>
                <i></i>
                <div>
                  <b>{phase.name}</b>
                  {phase.detail && <p>{phase.detail}</p>}
                </div>
                <span>{phase.state}</span>
              </article>
            ))}
            <div className="complete">
              <h2>
                {phases.some((p) => p.state === "failed")
                  ? "Scout Bee stopped safely."
                  : "The requested work completed."}
              </h2>
              <p>No secret values were written to the plan or log.</p>
              {connectionProfile && (
                <p>
                  The verified deployment is ready to connect to the ApiaryLens
                  Windows application. The connection file contains no
                  credentials.
                </p>
              )}
            </div>
            <div className="progress-actions">
              {connectionProfile && (
                <button onClick={saveConnectionProfile}>
                  Save Windows connection file
                </button>
              )}
              <button
                className="secondary"
                onClick={() => void saveDiagnostics()}
              >
                Save sanitized diagnostics
              </button>
              {phases.some((phase) => phase.state === "failed") && (
                <button onClick={() => void run("resume")}>
                  Resume safely
                </button>
              )}
            </div>
          </section>
        )}
        <footer>
          {step > 1 && step < 4 && (
            <button className="secondary" onClick={() => setStep(step - 1)}>
              Back
            </button>
          )}
          <span></span>
          {step === 1 && <button onClick={() => setStep(2)}>Continue</button>}
          {step === 2 && (
            <button onClick={() => setStep(3)}>Review plan</button>
          )}
          {step === 3 && (
            <>
              <button className="secondary" onClick={exportPlan}>
                Export plan
              </button>
              <button
                disabled={
                  busy ||
                  !release ||
                  (target === "cloudflare" && !costAcknowledged)
                }
                onClick={() => void run("dry-run")}
              >
                {busy ? "Checking…" : "Run preflight"}
              </button>
              {target !== "plan-only" && (
                <button
                  disabled={
                    busy ||
                    !release ||
                    (target === "cloudflare" && !costAcknowledged) ||
                    (target === "cloudflare" && cloudflareToken.length === 0) ||
                    (operation === "restore" && !restoreAcknowledged) ||
                    (operation === "restore" &&
                      target === "cloudflare" &&
                      form.backupFilePath.length === 0) ||
                    (target === "compose-ssh" &&
                      sshAuthMethod === "private-key" &&
                      sshPrivateKeyPath.length === 0) ||
                    (target === "compose-ssh" &&
                      sshAuthMethod === "password" &&
                      sshPassword.length === 0) ||
                    ((operation === "backup" || operation === "restore") &&
                      target === "windows-client" &&
                      form.windowsArchivePath.length === 0) ||
                    (operation === "install" &&
                      target !== "windows-client" &&
                      bootstrapToken.length < 16)
                  }
                  onClick={() => void run("apply")}
                >
                  Apply{" "}
                  {target === "windows-client"
                    ? "Windows lifecycle"
                    : "deployment"}
                </button>
              )}
            </>
          )}
          {busy && (
            <button className="danger" onClick={() => void cancel()}>
              Cancel safely
            </button>
          )}
        </footer>
      </main>
    </div>
  );
}
function CloudflareCostGuide() {
  return (
    <aside className="cost-guide" aria-labelledby="cloudflare-cost-heading">
      <div>
        <p className="eyebrow">Guarded family cost profile</p>
        <h2 id="cloudflare-cost-heading">
          Cloudflare Free allowances checked July 15, 2026
        </h2>
        <p>
          Scout Bee does not enable a paid plan. A modest family deployment is
          expected to fit within these allowances, but actual use and provider
          terms determine the bill.
        </p>
      </div>
      <dl>
        {cloudflareAllowances.map(([service, allowance]) => (
          <div key={service}>
            <dt>{service}</dt>
            <dd>{allowance}</dd>
          </div>
        ))}
      </dl>
      <p className="cost-note">
        Static Worker assets and R2 internet egress are currently free. Domain
        registration, backups outside this account, optional paid plans, and
        internet access are separate. Free-limit exhaustion can stop requests
        instead of producing a permanent-free guarantee.
      </p>
    </aside>
  );
}
function Field({
  label,
  name,
  value,
  update,
  placeholder,
}: {
  label: string;
  name: string;
  value: string;
  update: (n: string, v: string) => void;
  placeholder?: string;
}) {
  return (
    <label>
      {label}
      <input
        required
        name={name}
        value={value}
        placeholder={placeholder}
        onChange={(event) => update(name, event.target.value)}
      />
    </label>
  );
}
createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <App />
  </StrictMode>,
);
