$ErrorActionPreference="Stop"

$ROOT = Resolve-Path (Join-Path $PSScriptRoot "..\..")
$BUNDLE = Join-Path $ROOT "bundle\v1"
$OUT    = Join-Path $ROOT "out"

if(-not (Test-Path $BUNDLE)) { throw "MISSING_BUNDLE_DIR:$BUNDLE" }
New-Item -ItemType Directory -Force -Path $OUT | Out-Null

# SHA256SUMS.txt for bundle directory
$shaFile = Join-Path $BUNDLE "SHA256SUMS.txt"
Remove-Item -Force -ErrorAction SilentlyContinue $shaFile

$files = Get-ChildItem -Recurse -File -Path $BUNDLE | Where-Object { $_.Name -ne "SHA256SUMS.txt" }
foreach($f in $files){
  $h = (Get-FileHash -Algorithm SHA256 -Path $f.FullName).Hash.ToLower()
  $rel = $f.FullName.Substring($BUNDLE.Length).TrimStart('\')
  Add-Content -Encoding ASCII -NoNewline -Path $shaFile -Value ("$h  $rel`n")
}

# Create tar.gz (requires tar available on Windows 11)
$tgz = Join-Path $OUT "ZENODO_BUNDLE.tar.gz"
if(Test-Path $tgz){ Remove-Item -Force $tgz }

tar -C $BUNDLE -czf $tgz .

$tgzHash = (Get-FileHash -Algorithm SHA256 -Path $tgz).Hash.ToLower()
Set-Content -Encoding ASCII -NoNewline -Path (Join-Path $OUT "ZENODO_BUNDLE_SHA256.txt") -Value ("$tgzHash  ZENODO_BUNDLE.tar.gz")

"TGZ = $tgz"
"TGZ_SHA256 = $tgzHash"