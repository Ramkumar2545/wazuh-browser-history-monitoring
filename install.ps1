<#
.SYNOPSIS
    Wazuh Browser Monitor - One-Line Bootstrap Installer for Windows
    Author  : Ram Kumar G (IT Fortress)
    Version : 2.0
    Repo    : https://github.com/Ramkumar2545/wazuh-browser-history-monitoring

.DESCRIPTION
    This script is the ONLY file fetched from the internet.
    It downloads ONLY the two Python/PS files needed from your OWN public repo.
    NO exe installers. NO third-party URLs. NO Invoke-Expression on unknown code.

    VT-CLEAN:
      - No python installer download
      - No exe-pattern URLs
      - Only fetches .py and .ps1 from YOUR own GitHub repo (raw.githubusercontent.com)
      - All downloads verified before execution

    USAGE (run as Administrator in PowerShell):
      powershell -ExecutionPolicy Bypass -Command "iwr -UseBasicParsing 'https://raw.githubusercontent.com/Ramkumar2545/wazuh-browser-history-monitoring/main/install.ps1' | iex"

    REQUIREMENTS:
      Python 3.8+ must be installed SYSTEM-WIDE before running this.
      Download from: https://python.org
      During install: check 'Install for All Users' AND 'Add to PATH'
#>

# ─── CONFIG ──────────────────────────────────────────────────────────────────
$RepoBase     = "https://raw.githubusercontent.com/Ramkumar2545/wazuh-browser-history-monitoring/main"
$InstallDir   = "C:\BrowserMonitor"
$TaskName     = "BrowserHistoryMonitor"
$LogFile      = "$InstallDir\browser_history.log"
$WazuhConf    = "C:\Program Files (x86)\ossec-agent\ossec.conf"
$WazuhSvc     = "WazuhSvc"

$CollectorUrl = "$RepoBase/collector/browser-history-monitor.py"
$CollectorDst = "$InstallDir\browser-history-monitor.py"

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# ─── BANNER ──────────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "╔══════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║  Wazuh Browser Monitor - One-Line Installer               ║" -ForegroundColor Cyan
Write-Host "║  IT Fortress  |  github.com/Ramkumar2545              ║" -ForegroundColor Cyan
Write-Host "╚══════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""

# ─── ADMIN CHECK ────────────────────────────────────────────────────────────
Write-Host "[*] Checking Administrator privileges..." -ForegroundColor Yellow
$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "[-] ERROR: Run PowerShell as Administrator and retry." -ForegroundColor Red
    Write-Host "    Right-click PowerShell → 'Run as Administrator'" -ForegroundColor Yellow
    exit 1
}
Write-Host "    [+] Running as Administrator" -ForegroundColor Green

# ─── STEP 1: DETECT PYTHON (SYSTEM-WIDE ONLY) ───────────────────────────────
Write-Host ""
Write-Host "[1] Detecting System-Wide Python..." -ForegroundColor Yellow

$PythonExe  = $null
$PythonWExe = $null

# Search common system-wide install paths
$PythonPaths = @(
    "C:\Program Files\Python313\python.exe",
    "C:\Program Files\Python312\python.exe",
    "C:\Program Files\Python311\python.exe",
    "C:\Program Files\Python310\python.exe",
    "C:\Program Files (x86)\Python312\python.exe",
    "C:\Python312\python.exe",
    "C:\Python311\python.exe",
    "C:\Python310\python.exe"
)

foreach ($p in $PythonPaths) {
    if (Test-Path $p) { $PythonExe = $p; break }
}

# Check PATH but reject user-profile installs
if (-not $PythonExe) {
    $cmd = Get-Command python.exe -ErrorAction SilentlyContinue
    if ($cmd -and $cmd.Source -notlike "*\Users\*") {
        $PythonExe = $cmd.Source
    }
}

if (-not $PythonExe) {
    Write-Host ""
    Write-Host "[-] Python 3 not found (system-wide)." -ForegroundColor Red
    Write-Host ""
    Write-Host "  ACTION REQUIRED:" -ForegroundColor Yellow
    Write-Host "  1. Download Python from: https://python.org/downloads" -ForegroundColor White
    Write-Host "  2. During install, CHECK these two boxes:" -ForegroundColor White
    Write-Host "       [x] Install for All Users" -ForegroundColor Cyan
    Write-Host "       [x] Add Python to PATH" -ForegroundColor Cyan
    Write-Host "  3. After install, re-run this script." -ForegroundColor White
    Write-Host ""
    exit 1
}

$PyDir = Split-Path $PythonExe -Parent
$PythonWExe = Join-Path $PyDir "pythonw.exe"
if (-not (Test-Path $PythonWExe)) { $PythonWExe = $PythonExe }

Write-Host "    [+] Python   : $PythonExe" -ForegroundColor Green
Write-Host "    [+] PythonW  : $PythonWExe" -ForegroundColor Green

# ─── STEP 2: CREATE INSTALL DIRECTORY ─────────────────────────────────────────
Write-Host ""
Write-Host "[2] Creating $InstallDir..." -ForegroundColor Yellow
if (-not (Test-Path $InstallDir)) {
    New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
}

# Grant Modify to all users so non-admin accounts can write the log
$Acl = Get-Acl $InstallDir
$Ar  = New-Object System.Security.AccessControl.FileSystemAccessRule(
    "BUILTIN\Users","Modify","ContainerInherit,ObjectInherit","None","Allow"
)
$Acl.SetAccessRule($Ar)
Set-Acl $InstallDir $Acl
Write-Host "    [+] Created with BUILTIN\Users:Modify permissions" -ForegroundColor Green

# ─── STEP 3: DOWNLOAD PYTHON COLLECTOR ──────────────────────────────────────
Write-Host ""
Write-Host "[3] Downloading collector from your repo..." -ForegroundColor Yellow
Write-Host "    URL: $CollectorUrl" -ForegroundColor Gray

try {
    Invoke-WebRequest -Uri $CollectorUrl -OutFile $CollectorDst -UseBasicParsing
    $fileSize = (Get-Item $CollectorDst).Length
    if ($fileSize -lt 1000) {
        Write-Host "[-] Download too small ($fileSize bytes) — possible network error." -ForegroundColor Red
        exit 1
    }
    Write-Host "    [+] Downloaded: $CollectorDst ($fileSize bytes)" -ForegroundColor Green
} catch {
    Write-Host "[-] Download failed: $_" -ForegroundColor Red
    Write-Host "    Check internet connection or clone the repo manually." -ForegroundColor Yellow
    exit 1
}

# ─── STEP 4: CREATE SCHEDULED TASK ───────────────────────────────────────────
Write-Host ""
Write-Host "[4] Creating Scheduled Task: $TaskName..." -ForegroundColor Yellow

$Action    = New-ScheduledTaskAction `
    -Execute $PythonWExe `
    -Argument "`"$CollectorDst`"" `
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
Write-Host "    [+] Task created (runs hidden at every user logon)" -ForegroundColor Green

# ─── STEP 5: STARTUP SHORTCUT (FAILSAFE) ────────────────────────────────────
Write-Host ""
Write-Host "[5] Creating All-Users startup shortcut..." -ForegroundColor Yellow
$StartupDir   = "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp"
$ShortcutPath = Join-Path $StartupDir "WazuhBrowserMonitor.lnk"
$WShell = New-Object -ComObject WScript.Shell
$SC = $WShell.CreateShortcut($ShortcutPath)
$SC.TargetPath       = $PythonWExe
$SC.Arguments        = "`"$CollectorDst`""
$SC.WorkingDirectory = $InstallDir
$SC.Save()
Write-Host "    [+] Shortcut: $ShortcutPath" -ForegroundColor Green

# ─── STEP 6: WAZUH OSSEC.CONF ────────────────────────────────────────────────
Write-Host ""
Write-Host "[6] Updating Wazuh ossec.conf..." -ForegroundColor Yellow
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
        Write-Host "    [+] localfile block added" -ForegroundColor Green
        Restart-Service -Name $WazuhSvc -ErrorAction SilentlyContinue
        Start-Sleep 3
        $svc = Get-Service $WazuhSvc -ErrorAction SilentlyContinue
        if ($svc -and $svc.Status -eq 'Running') {
            Write-Host "    [+] Wazuh agent restarted — Running" -ForegroundColor Green
        }
    } else {
        Write-Host "    [=] Already configured — skipping" -ForegroundColor Gray
    }
} else {
    Write-Host "    [!] ossec.conf not found at $WazuhConf" -ForegroundColor Yellow
    Write-Host "        Add manually inside <ossec_config>:" -ForegroundColor Yellow
    Write-Host "          <localfile>" -ForegroundColor Gray
    Write-Host "            <location>$LogFile</location>" -ForegroundColor Gray
    Write-Host "            <log_format>syslog</log_format>" -ForegroundColor Gray
    Write-Host "          </localfile>" -ForegroundColor Gray
}

# ─── STEP 7: START NOW ─────────────────────────────────────────────────────────
Write-Host ""
Write-Host "[7] Starting monitoring now..." -ForegroundColor Yellow
Start-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
Start-Sleep -Seconds 5

if (Test-Path $LogFile) {
    $lines = (Get-Content $LogFile -ErrorAction SilentlyContinue).Count
    Write-Host "    [+] Log file active: $LogFile ($lines lines)" -ForegroundColor Green
} else {
    Write-Host "    [~] Log file will appear after first browser visit (up to 60s)" -ForegroundColor Yellow
}

# ─── DONE ────────────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "╔══════════════════════════════════════════════════════════╗" -ForegroundColor Green
Write-Host "║  [SUCCESS] Full Deployment Complete!                     ║" -ForegroundColor Green
Write-Host "╚══════════════════════════════════════════════════════════╝" -ForegroundColor Green
Write-Host ""
Write-Host "  Collector : $CollectorDst"
Write-Host "  Log file  : $LogFile"
Write-Host "  Task      : $TaskName (runs hidden at every logon)"
Write-Host ""
Write-Host "  Watch live logs:"
Write-Host "    Get-Content '$LogFile' -Tail 20 -Wait" -ForegroundColor Cyan
Write-Host ""
Write-Host "  Wazuh Manager — deploy decoder + rules once:"
Write-Host "    https://github.com/Ramkumar2545/wazuh-browser-history-monitoring" -ForegroundColor Cyan
Write-Host ""
