<#
.SYNOPSIS
  Build, verify and release Moon SSO to the Moon host.

.DESCRIPTION
  1. Runs the Go tests (unless -SkipTests).
  2. Cross-compiles a static linux/amd64 binary (CGO disabled).
  3. Uploads it to Moon and verifies the SHA-256 on both ends.
  4. Activates it on staging (migrate, restart, readiness) and runs smoke checks.
  5. Promotes the same digest to prod unless -StagingOnly; rolls back automatically on failure.
  6. Checks the public entry points from this machine.

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File deploy\deploy.ps1
  powershell -ExecutionPolicy Bypass -File deploy\deploy.ps1 -StagingOnly
#>
param(
  [switch]$SkipTests,
  [switch]$StagingOnly,
  [switch]$WithSDK,
  [string]$HostAlias = "moon"
)
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$server = Join-Path $root "server"
$dist = Join-Path $root "dist"
New-Item -ItemType Directory -Force $dist | Out-Null

function Invoke-Checked([string]$what, [scriptblock]$block) {
  Write-Host "==> $what" -ForegroundColor Cyan
  & $block
  if ($LASTEXITCODE -ne 0) { throw "$what failed (exit $LASTEXITCODE)" }
}

Push-Location $server
try {
  if (-not $SkipTests) {
    Invoke-Checked "go test" { go test -count=1 ./... }
  }
  $stamp = (Get-Date).ToUniversalTime().ToString("yyyyMMdd-HHmmss")
  $tmp = Join-Path $dist "moon-sso-build"
  $env:CGO_ENABLED = "0"; $env:GOOS = "linux"; $env:GOARCH = "amd64"
  try {
    Invoke-Checked "build linux/amd64" { go build -trimpath -ldflags "-s -w" -o $tmp ./cmd/moon-sso }
    $sha = (Get-FileHash -Algorithm SHA256 $tmp).Hash.ToLower()
    $version = "$stamp-$($sha.Substring(0, 8))"
    # Rebuild with the version stamped in (deterministic apart from the -X value).
    Invoke-Checked "stamp version $version" { go build -trimpath -ldflags "-s -w -X moon-sso/server/internal/app.Version=$version" -o $tmp ./cmd/moon-sso }
  } finally {
    Remove-Item Env:CGO_ENABLED, Env:GOOS, Env:GOARCH -ErrorAction SilentlyContinue
  }
  $artifact = Join-Path $dist "moon-sso-$version"
  Move-Item -Force $tmp $artifact
  $sha = (Get-FileHash -Algorithm SHA256 $artifact).Hash.ToLower()
  Write-Host "artifact $artifact sha256 $sha"
} finally {
  Pop-Location
}

$remoteRel = "/opt/moon-sso/releases/$version"
Invoke-Checked "upload release scripts" { scp -q (Join-Path $PSScriptRoot "remote\activate.sh") "${HostAlias}:/opt/moon-sso/bin/activate.sh" }
Invoke-Checked "create release dir" { ssh $HostAlias "install -d -m 0755 $remoteRel && chmod 0755 /opt/moon-sso/bin/activate.sh" }
Invoke-Checked "upload binary" { scp -q $artifact "${HostAlias}:$remoteRel/moon-sso.part" }
$remoteSha = (ssh $HostAlias "sha256sum $remoteRel/moon-sso.part | cut -d' ' -f1").Trim()
if ($remoteSha -ne $sha) { throw "checksum mismatch: local $sha remote $remoteSha" }
Invoke-Checked "finalize binary" { ssh $HostAlias "chmod 0755 $remoteRel/moon-sso.part && mv -f $remoteRel/moon-sso.part $remoteRel/moon-sso && echo $sha > $remoteRel/SHA256" }

Invoke-Checked "activate staging" { ssh $HostAlias "/opt/moon-sso/bin/activate.sh staging $version" }
Invoke-Checked "staging smoke" {
  ssh $HostAlias "set -e; curl -fsS http://127.0.0.1:8611/.well-known/openid-configuration >/dev/null; curl -fsS http://127.0.0.1:8611/.well-known/jwks.json | grep -q keys; curl -fsS -o /dev/null http://127.0.0.1:8611/login; echo staging-ok"
}

if ($WithSDK) {
  Push-Location $server
  try { Invoke-Checked "pack SDK artifacts" { go run ./cmd/sdkpack -repo .. -out ../dist/sdk } } finally { Pop-Location }
  $tgz = Join-Path $dist "sdk-$version.tgz"
  Invoke-Checked "archive SDK artifacts" { tar -czf $tgz -C (Join-Path $dist "sdk") . }
  Invoke-Checked "upload SDK artifacts" { scp -q $tgz "${HostAlias}:/tmp/moon-sso-sdk.tgz" }
  Invoke-Checked "publish SDK artifacts" {
    ssh $HostAlias "set -e; for d in /var/lib/moon-sso /var/lib/moon-sso-staging; do rm -rf `$d/sdk.new; mkdir -p `$d/sdk.new; tar -xzf /tmp/moon-sso-sdk.tgz -C `$d/sdk.new; chmod -R a+rX `$d/sdk.new; rm -rf `$d/sdk.old; [ -d `$d/sdk ] && mv `$d/sdk `$d/sdk.old; mv `$d/sdk.new `$d/sdk; rm -rf `$d/sdk.old; done; rm -f /tmp/moon-sso-sdk.tgz"
  }
}

if ($StagingOnly) {
  Write-Host "staging is running $version; prod untouched" -ForegroundColor Green
  exit 0
}

Invoke-Checked "activate prod" { ssh $HostAlias "/opt/moon-sso/bin/activate.sh prod $version" }

Write-Host "==> verify public entry points" -ForegroundColor Cyan
$ready = (Invoke-WebRequest -UseBasicParsing -Uri "https://sso.moonl.cloud/readyz" -TimeoutSec 15).Content.Trim()
if ($ready -ne "ready $version") { throw "public readyz returned '$ready', expected 'ready $version'" }
$disc = Invoke-RestMethod -Uri "https://sso.moonl.cloud/.well-known/openid-configuration" -TimeoutSec 15
if ($disc.issuer -ne "https://sso.moonl.cloud") { throw "unexpected issuer $($disc.issuer)" }
$admin = Invoke-WebRequest -UseBasicParsing -Uri "https://sso-admin.moonl.cloud/healthz" -TimeoutSec 15
if ($admin.StatusCode -ne 200) { throw "admin host unhealthy" }
Write-Host "prod is serving $version (sha256 $sha)" -ForegroundColor Green
