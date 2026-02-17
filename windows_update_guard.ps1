param(
  [ValidateSet('prep-update','disable-auto','enable-auto')]
  [string]$Mode = 'prep-update'
)

$ErrorActionPreference = 'Stop'

function Ensure-Admin {
  $id = [Security.Principal.WindowsIdentity]::GetCurrent()
  $p = New-Object Security.Principal.WindowsPrincipal($id)
  if (-not $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run this tool as Administrator.'
  }
}

function Ensure-Log {
  $root = Join-Path $env:ProgramData 'RootFix\logs'
  New-Item -ItemType Directory -Path $root -Force | Out-Null
  return (Join-Path $root ("windows-update-{0}.log" -f (Get-Date -Format yyyyMMdd-HHmmss)))
}

function Set-UpdatePolicy {
  param([bool]$DisableAuto)
  $base = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU'
  New-Item -Path $base -Force | Out-Null

  if ($DisableAuto) {
    New-ItemProperty -Path $base -Name NoAutoUpdate -PropertyType DWord -Value 1 -Force | Out-Null
    New-ItemProperty -Path $base -Name AUOptions -PropertyType DWord -Value 2 -Force | Out-Null
    Write-Host 'Automatic Windows Update disabled (manual checks still allowed).'
  }
  else {
    Remove-ItemProperty -Path $base -Name NoAutoUpdate -ErrorAction SilentlyContinue
    Remove-ItemProperty -Path $base -Name AUOptions -ErrorAction SilentlyContinue
    Write-Host 'Automatic Windows Update policy reset.'
  }
}

function Ensure-Services {
  Set-Service wuauserv -StartupType Manual -ErrorAction SilentlyContinue
  Set-Service UsoSvc -StartupType Manual -ErrorAction SilentlyContinue
  Start-Service wuauserv -ErrorAction SilentlyContinue
  Start-Service UsoSvc -ErrorAction SilentlyContinue
}

function Ensure-RestorePoint {
  try {
    Enable-ComputerRestore -Drive 'C:\' -ErrorAction SilentlyContinue
  }
  catch {
    Write-Warning "Enable-ComputerRestore failed: $($_.Exception.Message)"
  }

  try {
    Checkpoint-Computer -Description ("RootFix pre-update {0}" -f (Get-Date -Format s)) -RestorePointType 'MODIFY_SETTINGS'
    Write-Host 'Restore point created.'
  }
  catch {
    Write-Warning "Could not create restore point: $($_.Exception.Message)"
  }
}

Ensure-Admin
$log = Ensure-Log
Start-Transcript -Path $log -Force | Out-Null

try {
  switch ($Mode) {
    'prep-update' {
      Set-UpdatePolicy -DisableAuto $true
      Ensure-Services
      Ensure-RestorePoint
      Start-Process 'ms-settings:windowsupdate'
      Write-Host 'Windows Update page opened. Click Check for updates when ready.'
    }
    'disable-auto' {
      Set-UpdatePolicy -DisableAuto $true
    }
    'enable-auto' {
      Set-UpdatePolicy -DisableAuto $false
    }
  }

  Write-Host "Log saved to $log"
}
finally {
  Stop-Transcript | Out-Null
}
