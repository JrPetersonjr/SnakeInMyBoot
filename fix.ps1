param(
  [ValidateSet('auto','menu','full','kb','boot','repair')]
  [string]$Mode = 'auto',
  [string]$TargetKB = 'KB5077181',
  [string]$LogRoot = ''
)

$ErrorActionPreference = 'Continue'

function Run-Cmd {
  param([string]$Command)
  Write-Host "> $Command"
  cmd /c $Command
  $code = $LASTEXITCODE
  if ($code -ne 0) {
    Write-Warning "Command failed with exit code $code"
  }
  return $code
}

function Detect-WindowsDrive {
  $candidates = Get-PSDrive -PSProvider FileSystem | Sort-Object Name
  foreach ($drive in $candidates) {
    if (Test-Path "$($drive.Root)Windows\System32\Config\SYSTEM") {
      return $drive.Root.TrimEnd('\\')
    }
  }
  return $null
}

function Get-KBPackages {
  param([string]$WindowsDrive, [string]$KB)
  $tmp = Join-Path $env:TEMP ("dism-packages-{0}.txt" -f ([guid]::NewGuid().ToString('N')))
  cmd /c "dism /image:$WindowsDrive\ /get-packages > `"$tmp`""
  if (-not (Test-Path $tmp)) { return @() }

  $matches = @()
  $lines = Get-Content $tmp
  foreach ($line in $lines) {
    if ($line -match '^\s*Package Identity\s*:\s*(.+)$') {
      $pkg = $Matches[1].Trim()
      if ($pkg -match [regex]::Escape($KB)) {
        $matches += $pkg
      }
    }
  }

  Remove-Item $tmp -Force -ErrorAction SilentlyContinue
  return $matches | Select-Object -Unique
}

function Remove-KB {
  param([string]$WindowsDrive, [string]$KB)
  Write-Host "Checking for $KB in offline image..."
  $packages = Get-KBPackages -WindowsDrive $WindowsDrive -KB $KB
  if (-not $packages -or $packages.Count -eq 0) {
    Write-Host "$KB was not found in DISM package list."
    return $false
  }

  Write-Host "Found package(s):"
  $packages | ForEach-Object { Write-Host " - $_" }

  $removedAny = $false
  foreach ($pkg in $packages) {
    $code = Run-Cmd "dism /image:$WindowsDrive\ /remove-package /packagename:$pkg /norestart"
    if ($code -eq 0) { $removedAny = $true }
  }

  return $removedAny
}

function Disable-UpdatesOffline {
  param([string]$WindowsDrive)

  $softHive = "$WindowsDrive\Windows\System32\Config\SOFTWARE"
  $sysHive = "$WindowsDrive\Windows\System32\Config\SYSTEM"

  Write-Host "Applying offline Windows Update disable policy..."
  Run-Cmd "reg load HKLM\OFFSOFT \"$softHive\"" | Out-Null
  Run-Cmd "reg add HKLM\OFFSOFT\Policies\Microsoft\Windows\WindowsUpdate /f" | Out-Null
  Run-Cmd "reg add HKLM\OFFSOFT\Policies\Microsoft\Windows\WindowsUpdate\AU /v NoAutoUpdate /t REG_DWORD /d 1 /f" | Out-Null
  Run-Cmd "reg add HKLM\OFFSOFT\Policies\Microsoft\Windows\WindowsUpdate\AU /v AUOptions /t REG_DWORD /d 1 /f" | Out-Null
  Run-Cmd "reg unload HKLM\OFFSOFT" | Out-Null

  Run-Cmd "reg load HKLM\OFFSYS \"$sysHive\"" | Out-Null
  $selectOutput = cmd /c "reg query HKLM\OFFSYS\Select /v Current"
  $controlSet = 'ControlSet001'
  if ($selectOutput -match 'Current\s+REG_DWORD\s+0x([0-9a-fA-F]+)') {
    $num = [Convert]::ToInt32($Matches[1], 16)
    $controlSet = ('ControlSet{0:d3}' -f $num)
  }

  Run-Cmd "reg add HKLM\OFFSYS\$controlSet\Services\wuauserv /v Start /t REG_DWORD /d 4 /f" | Out-Null
  Run-Cmd "reg add HKLM\OFFSYS\$controlSet\Services\UsoSvc /v Start /t REG_DWORD /d 4 /f" | Out-Null
  Run-Cmd "reg unload HKLM\OFFSYS" | Out-Null

  Write-Host "Windows Update has been disabled offline (policy + services)."
}

function Clear-UpdateState {
  param([string]$WindowsDrive)

  Write-Host "Removing pending update metadata..."
  Remove-Item "$WindowsDrive\Windows\WinSxS\pending.xml","$WindowsDrive\Windows\WinSxS\cleanup.xml" -Force -ErrorAction SilentlyContinue

  Write-Host "Resetting SoftwareDistribution..."
  Run-Cmd "net stop wuauserv" | Out-Null
  Run-Cmd "net stop bits" | Out-Null
  if (Test-Path "$WindowsDrive\Windows\SoftwareDistribution") {
    Rename-Item "$WindowsDrive\Windows\SoftwareDistribution" "SoftwareDistribution.bak.$(Get-Date -f yyyyMMddHHmmss)" -ErrorAction SilentlyContinue
  }
  New-Item -ItemType Directory -Path "$WindowsDrive\Windows\SoftwareDistribution" -Force | Out-Null

  Write-Host "Resetting Catroot2..."
  Run-Cmd "net stop cryptsvc" | Out-Null
  if (Test-Path "$WindowsDrive\Windows\System32\catroot2") {
    Rename-Item "$WindowsDrive\Windows\System32\catroot2" "catroot2.bak.$(Get-Date -f yyyyMMddHHmmss)" -ErrorAction SilentlyContinue
  }
  New-Item -ItemType Directory -Path "$WindowsDrive\Windows\System32\catroot2" -Force | Out-Null
}

function Run-SystemRepair {
  param([string]$WindowsDrive)
  Run-Cmd "dism /image:$WindowsDrive\ /cleanup-image /restorehealth" | Out-Null
  Run-Cmd "sfc /scannow /offbootdir=$WindowsDrive\ /offwindir=$WindowsDrive\Windows" | Out-Null
}

function Run-BootRepair {
  param([string]$WindowsDrive)
  Run-Cmd "bootrec /scanos" | Out-Null
  Run-Cmd "bootrec /rebuildbcd" | Out-Null
  Run-Cmd "bootrec /fixmbr" | Out-Null
  $code = Run-Cmd "bootrec /fixboot"
  if ($code -ne 0) {
    Run-Cmd "bcdboot $WindowsDrive\Windows /f ALL" | Out-Null
  }
}

function Run-Full {
  param([string]$WindowsDrive, [string]$KB)
  Clear-UpdateState -WindowsDrive $WindowsDrive
  $kbRemoved = Remove-KB -WindowsDrive $WindowsDrive -KB $KB
  if ($kbRemoved) {
    Write-Host "$KB rollback attempted."
  }
  Disable-UpdatesOffline -WindowsDrive $WindowsDrive
  Run-SystemRepair -WindowsDrive $WindowsDrive
  Run-BootRepair -WindowsDrive $WindowsDrive
}

function Run-Auto {
  param([string]$WindowsDrive, [string]$KB)
  Write-Host "Auto mode: checking for likely bad update package $KB"
  $kbPresent = (Get-KBPackages -WindowsDrive $WindowsDrive -KB $KB).Count -gt 0

  if ($kbPresent) {
    Write-Host "$KB detected. Running targeted rollback + full repair + update disable."
    Run-Full -WindowsDrive $WindowsDrive -KB $KB
  } else {
    Write-Host "$KB not detected. Running standard full repair and disabling updates as a precaution."
    Clear-UpdateState -WindowsDrive $WindowsDrive
    Disable-UpdatesOffline -WindowsDrive $WindowsDrive
    Run-SystemRepair -WindowsDrive $WindowsDrive
    Run-BootRepair -WindowsDrive $WindowsDrive
  }
}

$WindowsDrive = Detect-WindowsDrive
if (-not $WindowsDrive) {
  throw 'Windows installation not found.'
}
Write-Host "Detected Windows at $WindowsDrive"
Write-Host "Target KB check: $TargetKB"

if ($LogRoot) {
  New-Item -ItemType Directory -Path $LogRoot -Force | Out-Null
  $logFile = Join-Path $LogRoot ("repair-{0}.log" -f (Get-Date -Format yyyyMMdd-HHmmss))
  Start-Transcript -Path $logFile -Force | Out-Null
  Write-Host "Logging transcript to: $logFile"
}

try {
  switch ($Mode) {
    'auto' {
      Run-Auto -WindowsDrive $WindowsDrive -KB $TargetKB
    }
    'full' {
      Run-Full -WindowsDrive $WindowsDrive -KB $TargetKB
    }
    'kb' {
      $removed = Remove-KB -WindowsDrive $WindowsDrive -KB $TargetKB
      if (-not $removed) {
        Write-Host "No matching KB package was removed."
      }
      Disable-UpdatesOffline -WindowsDrive $WindowsDrive
    }
    'boot' {
      Run-BootRepair -WindowsDrive $WindowsDrive
    }
    'repair' {
      Clear-UpdateState -WindowsDrive $WindowsDrive
      Run-SystemRepair -WindowsDrive $WindowsDrive
    }
    'menu' {
      Write-Host ''
      Write-Host 'Select repair mode:'
      Write-Host '1) Auto detect bad KB + full repair + disable updates'
      Write-Host '2) KB-only rollback check + disable updates'
      Write-Host '3) Full repair (all actions)'
      Write-Host '4) Boot repair only'
      Write-Host '5) Cache reset + DISM/SFC only'
      Write-Host '6) Exit'
      $choice = Read-Host 'Enter 1-6'
      switch ($choice) {
        '1' { Run-Auto -WindowsDrive $WindowsDrive -KB $TargetKB }
        '2' {
          $removed = Remove-KB -WindowsDrive $WindowsDrive -KB $TargetKB
          if (-not $removed) { Write-Host 'No matching KB package was removed.' }
          Disable-UpdatesOffline -WindowsDrive $WindowsDrive
        }
        '3' { Run-Full -WindowsDrive $WindowsDrive -KB $TargetKB }
        '4' { Run-BootRepair -WindowsDrive $WindowsDrive }
        '5' { Clear-UpdateState -WindowsDrive $WindowsDrive; Run-SystemRepair -WindowsDrive $WindowsDrive }
        default { Write-Host 'Exiting without changes.' }
      }
    }
  }

  Write-Host 'Repair routine complete. Reboot the system.'
}
finally {
  if ($LogRoot) {
    Stop-Transcript | Out-Null
  }
}
