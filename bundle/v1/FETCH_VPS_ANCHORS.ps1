param(
  [Parameter(Mandatory=$true)][string]$VpsHost,
  [Parameter(Mandatory=$true)][string]$VpsUser,
  [Parameter(Mandatory=$true)][string]$KeyPath
)

$ErrorActionPreference="Stop"

$ROOT   = "H:\AIActionFirewall_v1\level5_external_admit_authority"
$BUNDLE = Join-Path $ROOT "bundle\v1"
$ADIR   = Join-Path $BUNDLE "anchors"

if(-not (Test-Path $BUNDLE)) { throw "MISSING_BUNDLE_DIR:$BUNDLE" }
New-Item -ItemType Directory -Force -Path $ADIR | Out-Null

$R_ANC_LOG = "/opt/admit/anchors/anchors.log"

# Pull anchors.log
scp -i $KeyPath "${VpsUser}@${VpsHost}:$R_ANC_LOG" (Join-Path $ADIR "anchors.log")

# Determine latest ledger_root_*.txt from anchors.log (last line)
$last = Get-Content -Tail 1 (Join-Path $ADIR "anchors.log")
if(-not $last) { throw "EMPTY_ANCHORS_LOG" }

$parts = $last -split '\s\|\s'
if($parts.Count -lt 4) { throw "BAD_ANCHORS_LOG_FORMAT" }

$remoteOts = $parts[3].Trim()
$remoteTxt = $remoteOts -replace '\.ots$',''

# Pull latest txt + ots
scp -i $KeyPath "${VpsUser}@${VpsHost}:$remoteTxt" (Join-Path $ADIR ([IO.Path]::GetFileName($remoteTxt)))
scp -i $KeyPath "${VpsUser}@${VpsHost}:$remoteOts" (Join-Path $ADIR ([IO.Path]::GetFileName($remoteOts)))

"FETCH_OK"
Get-ChildItem -Path $ADIR | Select-Object Name,Length,LastWriteTime | Format-Table -AutoSize