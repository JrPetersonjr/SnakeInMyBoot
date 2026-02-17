param(
  [ValidateSet('auto','menu','full','kb','boot','repair','collect','undo')]
  [string]$Mode = 'auto',
  [string]$TargetKB = 'KB5077181',
  [string]$KbListPath = '',
  [string]$LogRoot = '',
  [string]$TelemetryConfigPath = ''
)

$ErrorActionPreference = 'Continue'
$Global:ActionState = [ordered]@{
  timestamp_utc = [DateTime]::UtcNow.ToString('o')
  mode = $Mode
  windows_drive = ''
  kb_targets = @()
  kb_detected = @()
  kb_removed = @()
  updates_disabled = $false
  updates_reenabled = $false
  bitlocker_locked = $false
  diagnostics_bundle = ''
  telemetry_email_sent = $false
  telemetry_github_sent = $false
}

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

function Test-BitLockerLocked {
  param([string]$WindowsDrive)
  $output = cmd /c "manage-bde -status $WindowsDrive 2>nul"
  if (-not $output) { return $false }
  return ($output -match 'Lock Status:\s+Locked')
}

function Get-TargetKBs {
  param([string]$DefaultKB, [string]$ListPath)
  $all = @($DefaultKB)
  if ($ListPath -and (Test-Path $ListPath)) {
    $extra = Get-Content $ListPath |
      ForEach-Object { $_.Trim() } |
      Where-Object { $_ -and -not $_.StartsWith('#') -and $_ -match '^KB\d+$' }
    $all += $extra
  }
  return $all | Select-Object -Unique
}

function Get-KBPackageMap {
  param([string]$WindowsDrive, [string[]]$KBs)
  $tmp = Join-Path $env:TEMP ("dism-packages-{0}.txt" -f ([guid]::NewGuid().ToString('N')))
  cmd /c "dism /image:$WindowsDrive\ /get-packages > `"$tmp`""
  if (-not (Test-Path $tmp)) { return @{} }

  $result = @{}
  foreach ($kb in $KBs) { $result[$kb] = @() }

  $lines = Get-Content $tmp
  foreach ($line in $lines) {
    if ($line -match '^\s*Package Identity\s*:\s*(.+)$') {
      $pkg = $Matches[1].Trim()
      foreach ($kb in $KBs) {
        if ($pkg -match [regex]::Escape($kb)) {
          $result[$kb] += $pkg
        }
      }
    }
  }

  Remove-Item $tmp -Force -ErrorAction SilentlyContinue
  foreach ($kb in $KBs) {
    $result[$kb] = $result[$kb] | Select-Object -Unique
  }
  return $result
}

function Remove-KBs {
  param([string]$WindowsDrive, [string[]]$KBs)
  $map = Get-KBPackageMap -WindowsDrive $WindowsDrive -KBs $KBs
  $removedAny = $false

  foreach ($kb in $KBs) {
    $packages = @($map[$kb])
    if ($packages.Count -eq 0) {
      Write-Host "$kb not found in DISM package list."
      continue
    }

    $Global:ActionState.kb_detected += $kb
    Write-Host "Found $kb package(s):"
    $packages | ForEach-Object { Write-Host " - $_" }

    foreach ($pkg in $packages) {
      $code = Run-Cmd "dism /image:$WindowsDrive\ /remove-package /packagename:$pkg /norestart"
      if ($code -eq 0) {
        $removedAny = $true
        $Global:ActionState.kb_removed += $kb
      }
    }
  }

  $Global:ActionState.kb_detected = $Global:ActionState.kb_detected | Select-Object -Unique
  $Global:ActionState.kb_removed = $Global:ActionState.kb_removed | Select-Object -Unique
  return $removedAny
}

function Get-ControlSet {
  param([string]$LoadedRoot)
  $selectOutput = cmd /c "reg query $LoadedRoot\Select /v Current"
  if ($selectOutput -match 'Current\s+REG_DWORD\s+0x([0-9a-fA-F]+)') {
    $num = [Convert]::ToInt32($Matches[1], 16)
    return ('ControlSet{0:d3}' -f $num)
  }
  return 'ControlSet001'
}

function Disable-UpdatesOffline {
  param([string]$WindowsDrive)

  $softHive = "$WindowsDrive\Windows\System32\Config\SOFTWARE"
  $sysHive = "$WindowsDrive\Windows\System32\Config\SYSTEM"

  Write-Host "Applying offline Windows Update block..."
  Run-Cmd "reg load HKLM\OFFSOFT \"$softHive\"" | Out-Null
  Run-Cmd "reg add HKLM\OFFSOFT\Policies\Microsoft\Windows\WindowsUpdate /f" | Out-Null
  Run-Cmd "reg add HKLM\OFFSOFT\Policies\Microsoft\Windows\WindowsUpdate\AU /v NoAutoUpdate /t REG_DWORD /d 1 /f" | Out-Null
  Run-Cmd "reg add HKLM\OFFSOFT\Policies\Microsoft\Windows\WindowsUpdate\AU /v AUOptions /t REG_DWORD /d 1 /f" | Out-Null
  Run-Cmd "reg unload HKLM\OFFSOFT" | Out-Null

  Run-Cmd "reg load HKLM\OFFSYS \"$sysHive\"" | Out-Null
  $controlSet = Get-ControlSet -LoadedRoot 'HKLM\OFFSYS'
  Run-Cmd "reg add HKLM\OFFSYS\$controlSet\Services\wuauserv /v Start /t REG_DWORD /d 4 /f" | Out-Null
  Run-Cmd "reg add HKLM\OFFSYS\$controlSet\Services\UsoSvc /v Start /t REG_DWORD /d 4 /f" | Out-Null
  Run-Cmd "reg unload HKLM\OFFSYS" | Out-Null

  $Global:ActionState.updates_disabled = $true
  Write-Host "Windows Update disabled offline."
}

function Enable-UpdatesOffline {
  param([string]$WindowsDrive)

  $softHive = "$WindowsDrive\Windows\System32\Config\SOFTWARE"
  $sysHive = "$WindowsDrive\Windows\System32\Config\SYSTEM"

  Write-Host "Removing offline Windows Update block..."
  Run-Cmd "reg load HKLM\OFFSOFT \"$softHive\"" | Out-Null
  Run-Cmd "reg delete HKLM\OFFSOFT\Policies\Microsoft\Windows\WindowsUpdate\AU /f" | Out-Null
  Run-Cmd "reg delete HKLM\OFFSOFT\Policies\Microsoft\Windows\WindowsUpdate /f" | Out-Null
  Run-Cmd "reg unload HKLM\OFFSOFT" | Out-Null

  Run-Cmd "reg load HKLM\OFFSYS \"$sysHive\"" | Out-Null
  $controlSet = Get-ControlSet -LoadedRoot 'HKLM\OFFSYS'
  Run-Cmd "reg add HKLM\OFFSYS\$controlSet\Services\wuauserv /v Start /t REG_DWORD /d 3 /f" | Out-Null
  Run-Cmd "reg add HKLM\OFFSYS\$controlSet\Services\UsoSvc /v Start /t REG_DWORD /d 3 /f" | Out-Null
  Run-Cmd "reg unload HKLM\OFFSYS" | Out-Null

  $Global:ActionState.updates_reenabled = $true
  Write-Host "Windows Update re-enabled offline."
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

function Collect-Diagnostics {
  param([string]$WindowsDrive, [string]$Root)

  $stamp = Get-Date -Format yyyyMMdd-HHmmss
  $bundleDir = Join-Path $Root "bundle-$stamp"
  New-Item -ItemType Directory -Path $bundleDir -Force | Out-Null

  cmd /c "dism /image:$WindowsDrive\ /get-packages > `"$bundleDir\dism-packages.txt`" 2>&1"
  cmd /c "bcdedit /enum all > `"$bundleDir\bcdedit.txt`" 2>&1"
  cmd /c "manage-bde -status > `"$bundleDir\bitlocker-status.txt`" 2>&1"
  cmd /c "wmic diskdrive get model,status,size > `"$bundleDir\disk-health.txt`" 2>&1"
  cmd /c "chkdsk $WindowsDrive > `"$bundleDir\chkdsk.txt`" 2>&1"

  $cbs = "$WindowsDrive\Windows\Logs\CBS\CBS.log"
  $dism = "$WindowsDrive\Windows\Logs\DISM\dism.log"
  if (Test-Path $cbs) { Copy-Item $cbs "$bundleDir\CBS.log" -Force }
  if (Test-Path $dism) { Copy-Item $dism "$bundleDir\dism.log" -Force }

  $zipPath = "$bundleDir.zip"
  try {
    Compress-Archive -Path "$bundleDir\*" -DestinationPath $zipPath -Force
    $Global:ActionState.diagnostics_bundle = $zipPath
    Write-Host "Diagnostics bundle created: $zipPath"
  }
  catch {
    $Global:ActionState.diagnostics_bundle = $bundleDir
    Write-Host "Diagnostics folder created: $bundleDir"
  }
}

function Write-ActionsReport {
  param([string]$Root)
  if (-not $Root) { return }
  $Global:ActionState.timestamp_utc = [DateTime]::UtcNow.ToString('o')
  $path = Join-Path $Root ("actions-{0}.json" -f (Get-Date -Format yyyyMMdd-HHmmss))
  $Global:ActionState | ConvertTo-Json -Depth 4 | Set-Content -Path $path -Encoding ASCII
  Write-Host "Action report: $path"
}

function Send-Telemetry {
  param([string]$Root, [string]$ConfigPath)
  if (-not $ConfigPath -or -not (Test-Path $ConfigPath)) { return }

  try {
    . $ConfigPath
  }
  catch {
    Write-Warning "Telemetry config failed to load: $ConfigPath"
    return
  }

  if (-not $RootFixTelemetry) { return }

  $latestLog = Get-ChildItem $Root -Filter '*.log' -File | Sort-Object LastWriteTime -Descending | Select-Object -First 1
  $payloadPath = $latestLog.FullName
  if ($Global:ActionState.diagnostics_bundle -and (Test-Path $Global:ActionState.diagnostics_bundle)) {
    $payloadPath = $Global:ActionState.diagnostics_bundle
  }

  if ($RootFixTelemetry.EnableEmail -and $payloadPath) {
    try {
      if (Get-Command Send-MailMessage -ErrorAction SilentlyContinue) {
        $secure = ConvertTo-SecureString $RootFixTelemetry.GmailAppPassword -AsPlainText -Force
        $cred = New-Object System.Management.Automation.PSCredential($RootFixTelemetry.GmailFrom, $secure)
        Send-MailMessage -SmtpServer 'smtp.gmail.com' -Port 587 -UseSsl -Credential $cred -From $RootFixTelemetry.GmailFrom -To $RootFixTelemetry.GmailTo -Subject "RootFix log $(Get-Date -Format s)" -Body "Attached RootFix log from $env:COMPUTERNAME" -Attachments $payloadPath
        $Global:ActionState.telemetry_email_sent = $true
      }
    }
    catch {
      Write-Warning "Email telemetry failed: $($_.Exception.Message)"
    }
  }

  if ($RootFixTelemetry.EnableGitHubUpload -and $payloadPath) {
    try {
      $bytes = [System.IO.File]::ReadAllBytes($payloadPath)
      $content = [Convert]::ToBase64String($bytes)
      $datePart = Get-Date -Format yyyyMMdd-HHmmss
      $name = [System.IO.Path]::GetFileName($payloadPath)
      $repoPath = "$($RootFixTelemetry.GitHubPathPrefix)/$env:COMPUTERNAME-$datePart-$name"
      $uri = "https://api.github.com/repos/$($RootFixTelemetry.GitHubOwner)/$($RootFixTelemetry.GitHubRepo)/contents/$repoPath"
      $body = @{
        message = "Upload RootFix log $datePart"
        content = $content
        branch  = $RootFixTelemetry.GitHubBranch
      } | ConvertTo-Json
      $headers = @{ Authorization = "Bearer $($RootFixTelemetry.GitHubToken)"; 'User-Agent' = 'RootFix' }
      Invoke-RestMethod -Uri $uri -Method Put -Headers $headers -Body $body -ContentType 'application/json' | Out-Null
      $Global:ActionState.telemetry_github_sent = $true
    }
    catch {
      Write-Warning "GitHub telemetry failed: $($_.Exception.Message)"
    }
  }
}

$WindowsDrive = Detect-WindowsDrive
if (-not $WindowsDrive) {
  throw 'Windows installation not found. If BitLocker is enabled, unlock first in Command Prompt.'
}

if (Test-BitLockerLocked -WindowsDrive $WindowsDrive) {
  $Global:ActionState.bitlocker_locked = $true
  throw "BitLocker volume is locked: $WindowsDrive. Run: manage-bde -unlock $WindowsDrive -RecoveryPassword <YOUR-48-DIGIT-KEY>"
}

$Global:ActionState.windows_drive = $WindowsDrive
$kbTargets = Get-TargetKBs -DefaultKB $TargetKB -ListPath $KbListPath
$Global:ActionState.kb_targets = $kbTargets

Write-Host "Detected Windows at $WindowsDrive"
Write-Host "KB targets: $($kbTargets -join ', ')"

if ($LogRoot) {
  New-Item -ItemType Directory -Path $LogRoot -Force | Out-Null
  $logFile = Join-Path $LogRoot ("repair-{0}.log" -f (Get-Date -Format yyyyMMdd-HHmmss))
  Start-Transcript -Path $logFile -Force | Out-Null
  Write-Host "Logging transcript to: $logFile"
}

try {
  switch ($Mode) {
    'auto' {
      $present = (Get-KBPackageMap -WindowsDrive $WindowsDrive -KBs $kbTargets)
      $hasTarget = $false
      foreach ($kb in $kbTargets) { if (@($present[$kb]).Count -gt 0) { $hasTarget = $true } }

      if ($hasTarget) {
        Write-Host "Target KB found. Running rollback + full repair + update block."
      }
      else {
        Write-Host "Target KB not found. Running standard full repair + update block."
      }
      Clear-UpdateState -WindowsDrive $WindowsDrive
      Remove-KBs -WindowsDrive $WindowsDrive -KBs $kbTargets | Out-Null
      Disable-UpdatesOffline -WindowsDrive $WindowsDrive
      Run-SystemRepair -WindowsDrive $WindowsDrive
      Run-BootRepair -WindowsDrive $WindowsDrive
    }
    'kb' {
      Remove-KBs -WindowsDrive $WindowsDrive -KBs $kbTargets | Out-Null
      Disable-UpdatesOffline -WindowsDrive $WindowsDrive
    }
    'full' {
      Clear-UpdateState -WindowsDrive $WindowsDrive
      Remove-KBs -WindowsDrive $WindowsDrive -KBs $kbTargets | Out-Null
      Disable-UpdatesOffline -WindowsDrive $WindowsDrive
      Run-SystemRepair -WindowsDrive $WindowsDrive
      Run-BootRepair -WindowsDrive $WindowsDrive
    }
    'boot' {
      Run-BootRepair -WindowsDrive $WindowsDrive
    }
    'repair' {
      Clear-UpdateState -WindowsDrive $WindowsDrive
      Run-SystemRepair -WindowsDrive $WindowsDrive
    }
    'collect' {
      Collect-Diagnostics -WindowsDrive $WindowsDrive -Root $LogRoot
    }
    'undo' {
      Enable-UpdatesOffline -WindowsDrive $WindowsDrive
      Write-Host 'Undo complete. Windows Update should be re-enabled on next boot.'
    }
    'menu' {
      Write-Host 'Use fixme.bat menu to run modes in WinRE.'
    }
  }

  if ($LogRoot) {
    Collect-Diagnostics -WindowsDrive $WindowsDrive -Root $LogRoot
    Write-ActionsReport -Root $LogRoot
    Send-Telemetry -Root $LogRoot -ConfigPath $TelemetryConfigPath
  }

  Write-Host 'Repair routine complete. Reboot the system.'
}
finally {
  if ($LogRoot) {
    Stop-Transcript | Out-Null
  }
}
