<#
.SYNOPSIS
  Copy Moon SSO's encrypted backups to this PC (off-host copy) and verify checksums.

.DESCRIPTION
  Backups are created daily on Moon at 19:30 UTC by moon-sso-backup.timer and are
  encrypted with /etc/moon-sso/backup.key — keep that key (and /etc/moon-sso/master.key)
  in an offline safe place; they are NOT copied by this script.

  Schedule daily, e.g. in an elevated PowerShell:
    schtasks /Create /SC DAILY /ST 06:00 /TN "MoonSSO-Backup-Pull" /TR "powershell -NoProfile -ExecutionPolicy Bypass -File C:\develop\moon-sso\deploy\pull-backups.ps1"
#>
param(
  [string]$Destination = "D:\Backups\moon-sso",
  [string]$HostAlias = "moon",
  [int]$KeepDays = 60
)
$ErrorActionPreference = "Stop"
New-Item -ItemType Directory -Force $Destination | Out-Null
$remote = (ssh $HostAlias "ls -1 /var/backups/moon-sso/ | grep -E '\.enc(\.sha256)?$'") -split "`n" | Where-Object { $_ }
foreach ($name in $remote) {
  $local = Join-Path $Destination $name
  if (-not (Test-Path $local)) {
    scp -q "${HostAlias}:/var/backups/moon-sso/$name" $local
    if ($LASTEXITCODE -ne 0) { throw "scp failed for $name" }
    Write-Host "pulled $name"
  }
}
Get-ChildItem $Destination -Filter "*.enc" | ForEach-Object {
  $sumFile = "$($_.FullName).sha256"
  if (Test-Path $sumFile) {
    $want = ((Get-Content $sumFile) -split '\s+')[0]
    $got = (Get-FileHash -Algorithm SHA256 $_.FullName).Hash.ToLower()
    if ($want -ne $got) { throw "checksum mismatch: $($_.Name)" }
  }
}
Get-ChildItem $Destination -File | Where-Object { $_.LastWriteTime -lt (Get-Date).AddDays(-$KeepDays) } | Remove-Item -Force
Write-Host "backups in $Destination verified"
