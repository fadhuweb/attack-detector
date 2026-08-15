param(
  [Parameter(Mandatory=$true)][string]$User,   # your VM username
  [int]$Port = 2222,                            # 2222 target, 2223 attacker
  [string]$Target = "localhost"
)
$repo = Split-Path -Parent $PSScriptRoot
Write-Host "Syncing $repo -> ${User}@${Target}:~/attack-detector (port $Port)"
scp -P $Port -r "$repo" "${User}@${Target}:~/"
Write-Host "Done. On the target:  cd ~/attack-detector && ./scripts/run.sh"
