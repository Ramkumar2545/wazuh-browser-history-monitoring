<#
.SYNOPSIS
    Wazuh Browser Monitor - Windows Installer
    Author  : Ram Kumar G (IT Fortress)
    Version : 2.0

.DESCRIPTION
    Installs the browser-history-monitor.py collector locally.
    Sets up a Scheduled Task to run at every user logon.
    Updates Wazuh agent ossec.conf with the localfile block.

    VT-CLEAN:
      - NO Invoke-WebRequest (no internet downloads)
      - NO exe installer downloads
      - NO remote script fetching
      - Script is copied from this local repo only

    REQUIREMENTS:
      1. Run this script as Administrator.
      2. Python 3.8+ must already be installed SYSTEM-WIDE:
         Download from https://python.org
         During install: check "Install for All Users" AND "Add Python to PATH"

.USAGE
    powershell.exe -ExecutionPolicy Bypass -File windows-installer.ps1
#>

# ─── CONFIG ───────────────────────────────────────────────────────────────────
$InstallDir   = "C:\BrowserMonitor"
$ScriptName   = "browser-history-monitor.py"
$TaskName     = "BrowserHistoryMonitor"
$LogFile      = "$InstallDir\browser_history.log"
$WazuhConf    = "C:\Program Files (x86)\ossec-agent\ossec.conf"
$WazuhSvc     = "WazuhSvc"

# Source: relative path within this repo
$RepoRoot     = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Definition)
$SourceScript = Join-Path $RepoRoot "collector\$ScriptName"
$DestScript   = Join-Path $InstallDir $ScriptName

# ─── BANNER ───────────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "╔══════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║  Wazuh Browser Monitor - Windows Installer               ║" -ForegroundColor Cyan
Write-Host "║  IT Fortress | VT-Clean | No Internet Downloads          ║" -ForegroundColor Cyan
Write-Host "╚══════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""

# ─── ADMIN CHECK ──────────────────────────────────────────────────────────────
$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "[-] ERROR: Run this script as Administrator." -ForegroundColor Red
    exit 1
}

# ─── STEP 1: PYTHON DETECTION ─────────────────────────────────────────────────
Write-Host "[1] Detecting Python (System-Wide)..." -ForegroundColor Yellow

$PythonExe  = $null
$PythonWExe = $null

$CommonPaths = @(
    "C:\Program Files\Python313\python.exe",
    "C:\Program Files\Python312\python.exe",
    "C:\Program Files\Python311\python.exe",
    "C:\Program Files\Python310\python.exe",
    "C:\Program Files (x86)\Python312\python.exe",
    "C:\Python312\python.exe",
    "C:\Python311\python.exe"
)

foreach ($path in $CommonPaths) {
    if (Test-Path $path) {
        $PythonExe = $path
        Write-Host "    [+] Found: $path" -ForegroundColor Green
        break
    }
}

# Also check PATH — but reject user-specific installs
if (-not $PythonExe) {
    $cmd = Get-Command python.exe -ErrorAction SilentlyContinue
    if ($cmd) {
        if ($cmd.Source -notlike "*\Users\*") {
            $PythonExe = $cmd.Source
            Write-Host "    [+] Found via PATH: $PythonExe" -ForegroundColor Green
        } else {
            Write-Host "    [!] Found Python at $($cmd.Source)" -ForegroundColor Yellow
            Write-Host "        BUT it is user-specific (AppData) — non-admin users cannot run it." -ForegroundColor Yellow
            Write-Host "        Please reinstall Python with 'Install for All Users' checked." -ForegroundColor Yellow
        }
    }
}

if (-not $PythonExe) {
    Write-Host ""
    Write-Host "[-] Python not found in any system-wide location." -ForegroundColor Red
    Write-Host "    Please install Python 3.x from https://python.org" -ForegroundColor Red
    Write-Host "    During install: check 'Install for All Users' AND 'Add to PATH'" -ForegroundColor Red
    Write-Host "    Then re-run this script." -ForegroundColor Red
    exit 1
}

# Find pythonw.exe (windowless — no console popup)
$PyDir      = Split-Path $PythonExe -Parent
$PythonWExe = Join-Path $PyDir "pythonw.exe"
if (-not (Test-Path $PythonWExe)) {
    Write-Host "    [!] pythonw.exe not found, falling back to python.exe" -ForegroundColor Yellow
    $PythonWExe = $PythonExe
} else {
    Write-Host "    [+] Windowless Python: $PythonWExe" -ForegroundColor Green
}

# ─── STEP 2: VERIFY SOURCE SCRIPT EXISTS ──────────────────────────────────────
Write-Host ""
Write-Host "[2] Verifying collector script..." -ForegroundColor Yellow
if (-not (Test-Path $SourceScript)) {
    Write-Host "[-] Collector script not found at: $SourceScript" -ForegroundColor Red
    Write-Host "    Make sure you cloned the full repo and run from the installers\ folder." -ForegroundColor Red
    exit 1
}
Write-Host "    [+] Found: $SourceScript" -ForegroundColor Green

# ─── STEP 3: CREATE INSTALL DIRECTORY ────────────────────────────────────────
Write-Host ""
Write-Host "[3] Creating $InstallDir..." -ForegroundColor Yellow
if (-not (Test-Path $InstallDir)) {
    New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
}

# Grant BUILTIN\Users Modify permission so non-admin users can write the log
$Acl = Get-Acl $InstallDir
$Ar  = New-Object System.Security.AccessControl.FileSystemAccessRule(
    "BUILTIN\Users", "Modify", "ContainerInherit,ObjectInherit", "None", "Allow"
)
$Acl.SetAccessRule($Ar)
Set-Acl $InstallDir $Acl
Write-Host "    [+] Permissions granted (BUILTIN\Users: Modify)" -ForegroundColor Green

# ─── STEP 4: COPY COLLECTOR ───────────────────────────────────────────────────
Write-Host ""
Write-Host "[4] Copying collector script..." -ForegroundColor Yellow
Copy-Item -Path $SourceScript -Destination $DestScript -Force
Write-Host "    [+] Copied to $DestScript" -ForegroundColor Green

# ─── STEP 5: CREATE SCHEDULED TASK ───────────────────────────────────────────
Write-Host ""
Write-Host "[5] Creating Scheduled Task: $TaskName..." -ForegroundColor Yellow

$Action    = New-ScheduledTaskAction `
    -Execute $PythonWExe `
    -Argument "`"$DestScript`"" `
    -WorkingDirectory $InstallDir

$Trigger   = New-ScheduledTaskTrigger -AtLogon
$Principal = New-ScheduledTaskPrincipal -GroupId "BUILTIN\Users" -RunLevel Limited
$Settings  = New-ScheduledTaskSettingsSet `
    -Hidden `
    -AllowStartIfOnBatteries `
    -DontStopIfGoingOnBatteries `
    -ExecutionTimeLimit ([TimeSpan]::Zero)

Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
Register-ScheduledTask -TaskName $TaskName -Action $Action -Trigger $Trigger -Principal $Principal | Out-Null
Set-ScheduledTask -TaskName $TaskName -Settings $Settings | Out-Null
Write-Host "    [+] Scheduled Task created (runs at every logon, hidden, all users)" -ForegroundColor Green

# ─── STEP 6: STARTUP SHORTCUT (FAILSAFE) ─────────────────────────────────────
Write-Host ""
Write-Host "[6] Creating All Users startup shortcut..." -ForegroundColor Yellow
$StartupDir  = "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp"
$ShortcutPath = Join-Path $StartupDir "WazuhBrowserMonitor.lnk"
$WShell  = New-Object -ComObject WScript.Shell
$SC = $WShell.CreateShortcut($ShortcutPath)
$SC.TargetPath      = $PythonWExe
$SC.Arguments       = "`"$DestScript`""
$SC.WorkingDirectory = $InstallDir
$SC.Save()
Write-Host "    [+] Shortcut: $ShortcutPath" -ForegroundColor Green

# ─── STEP 7: WAZUH OSSEC.CONF ────────────────────────────────────────────────
Write-Host ""
Write-Host "[7] Updating Wazuh ossec.conf..." -ForegroundColor Yellow
$Marker = "<!-- BROWSER_MONITOR -->"

if (Test-Path $WazuhConf) {
    $Content = Get-Content $WazuhConf -Raw
    if ($Content -notmatch [regex]::Escape($Marker)) {
        $Block = @"

  <!-- BROWSER_MONITOR -->
  <localfile>
    <location>$LogFile</location>
    <log_format>syslog</log_format>
  </localfile>
"@
        $Content = $Content -replace "</ossec_config>", "$Block`n</ossec_config>"
        Set-Content -Path $WazuhConf -Value $Content -Encoding UTF8
        Write-Host "    [+] localfile block added to ossec.conf" -ForegroundColor Green

        # Restart Wazuh agent
        Restart-Service -Name $WazuhSvc -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 3
        $svc = Get-Service $WazuhSvc -ErrorAction SilentlyContinue
        if ($svc -and $svc.Status -eq 'Running') {
            Write-Host "    [+] Wazuh agent: Running" -ForegroundColor Green
        } else {
            Write-Host "    [!] Wazuh agent may need manual restart." -ForegroundColor Yellow
        }
    } else {
        Write-Host "    [=] localfile block already present — skipping" -ForegroundColor Gray
    }
} else {
    Write-Host "    [!] ossec.conf not found at $WazuhConf" -ForegroundColor Yellow
    Write-Host "        Add this block manually inside <ossec_config>:" -ForegroundColor Yellow
    Write-Host "          <localfile>" -ForegroundColor Gray
    Write-Host "            <location>$LogFile</location>" -ForegroundColor Gray
    Write-Host "            <log_format>syslog</log_format>" -ForegroundColor Gray
    Write-Host "          </localfile>" -ForegroundColor Gray
}

# Remove old launcher.bat if left from previous version
if (Test-Path "$InstallDir\launcher.bat") { Remove-Item "$InstallDir\launcher.bat" -Force }

# ─── DONE ─────────────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "╔══════════════════════════════════════════════════════════╗" -ForegroundColor Green
Write-Host "║  [SUCCESS] Installation Complete!                        ║" -ForegroundColor Green
Write-Host "╚══════════════════════════════════════════════════════════╝" -ForegroundColor Green
Write-Host ""
Write-Host "  To start monitoring NOW (without reboot):"
Write-Host "    Start-ScheduledTask -TaskName '$TaskName'" -ForegroundColor Cyan
Write-Host ""
Write-Host "  Log file: $LogFile"
Write-Host "  Watch:    Get-Content '$LogFile' -Tail 20 -Wait"
Write-Host ""
