# NOT PACKED FOR RELEASE, NOT PUSHED. Submission locked until GV4.
# Seeded at C2 (Phase P2 Track Release-eng) from the DIST-002 drafts.
# Placeholders {VERSION} and {SHA256_EXE_AMD64} are substituted by the release
# workflow from the published release SHA256SUMS.
$ErrorActionPreference = 'Stop'
$toolsDir = Split-Path -Parent $MyInvocation.MyCommand.Definition

# Download the exact attested release asset; keep a stable local name so the
# shimgen shim is always `scout-bee`. (Download-at-install from the official
# distribution point avoids the embedded-binary VERIFICATION.txt path and
# keeps one canonical binary: the attested GitHub release asset.)
$packageArgs = @{
  packageName    = $env:ChocolateyPackageName
  fileFullPath   = Join-Path $toolsDir 'scout-bee.exe'
  url64bit       = 'https://github.com/ApiaryLens/scout-bee/releases/download/v{VERSION}/scout-bee-{VERSION}-windows-amd64.exe' # placeholder
  checksum64     = '{SHA256_EXE_AMD64}' # placeholder
  checksumType64 = 'sha256'
}

Get-ChocolateyWebFile @packageArgs

# Shimgen automatically shims scout-bee.exe onto PATH; no .gui marker —
# Scout Bee is launched from a console and opens its guide UI itself.

# Dual-updater suppression mirror of the app-side R3 rule: mark this install
# as package-manager owned so Scout's self-update suppresses self-apply.
# Marker path/schema is finalized by the R3 design detail.
$markerDir = Join-Path $env:LOCALAPPDATA 'ScoutBee\lifecycle'
New-Item -ItemType Directory -Force -Path $markerDir | Out-Null
@{ source = 'chocolatey'; packageVersion = '{VERSION}' } |
  ConvertTo-Json | Set-Content -Path (Join-Path $markerDir 'package-manager.json') -Encoding utf8
