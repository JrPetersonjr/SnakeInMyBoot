Write-Host "Starting RootSignal Windows Repair..."

$os = Get-PSDrive -PSProvider FileSystem |
  Where-Object { Test-Path "$($_.Root)Windows\System32\Config\SYSTEM" } |
  Select-Object -First 1
if (-not $os) { throw "Windows installation not found." }
$W = $os.Root.TrimEnd('\\')
Write-Host "Detected Windows at $W"

Remove-Item "$W\Windows\WinSxS\pending.xml","$W\Windows\WinSxS\cleanup.xml" -Force -ErrorAction SilentlyContinue

cmd /c "net stop wuauserv" | Out-Null
cmd /c "net stop bits" | Out-Null
if (Test-Path "$W\Windows\SoftwareDistribution") {
  Rename-Item "$W\Windows\SoftwareDistribution" "SoftwareDistribution.bak.$(Get-Date -f yyyyMMddHHmmss)" -ErrorAction SilentlyContinue
}
New-Item -ItemType Directory -Path "$W\Windows\SoftwareDistribution" -Force | Out-Null

cmd /c "net stop cryptsvc" | Out-Null
if (Test-Path "$W\Windows\System32\catroot2") {
  Rename-Item "$W\Windows\System32\catroot2" "catroot2.bak.$(Get-Date -f yyyyMMddHHmmss)" -ErrorAction SilentlyContinue
}
New-Item -ItemType Directory -Path "$W\Windows\System32\catroot2" -Force | Out-Null

cmd /c "dism /image:$W\ /cleanup-image /restorehealth"
cmd /c "sfc /scannow /offbootdir=$W\ /offwindir=$W\Windows"

cmd /c "bootrec /scanos"
cmd /c "bootrec /rebuildbcd"
cmd /c "bootrec /fixmbr"
cmd /c "bootrec /fixboot"
if ($LASTEXITCODE -ne 0) { cmd /c "bcdboot $W\Windows /f ALL" }

Write-Host "Repair complete. Reboot the system."
