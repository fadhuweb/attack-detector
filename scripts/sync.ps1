# Copy the repo from the Windows workstation to the target VM.
# Usage:  .\scripts\sync.ps1 [-User fadhl] [-Target 192.168.50.10]
param(
    [string]$User = "fadhl",
    [string]$Target = "192.168.50.10",
    [string]$Dest = "~/attack-detector"
)

$root = Split-Path -Parent $PSScriptRoot

Write-Host "==> Syncing $root -> ${User}@${Target}:${Dest}"

# Excludes the venv and logs; those belong to the target, not the workstation.
$exclude = @(".venv", "logs", "__pycache__", ".git")

$staging = Join-Path $env:TEMP "attack-detector-sync"
if (Test-Path $staging) { Remove-Item -Recurse -Force $staging }
New-Item -ItemType Directory -Path $staging | Out-Null

Get-ChildItem -Path $root -Force | Where-Object { $exclude -notcontains $_.Name } | ForEach-Object {
    Copy-Item -Path $_.FullName -Destination $staging -Recurse -Force
}

ssh "${User}@${Target}" "mkdir -p $Dest"

# One scp per top-level entry: PowerShell does not expand a "$staging/*" glob,
# and scp would receive the asterisk literally.
Get-ChildItem -Path $staging -Force | ForEach-Object {
    scp -r $_.FullName "${User}@${Target}:${Dest}/"
}

ssh "${User}@${Target}" "chmod +x $Dest/scripts/*.sh"

Remove-Item -Recurse -Force $staging
Write-Host "==> Done. On the target:  cd $Dest && ./scripts/run.sh"
